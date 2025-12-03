from fastapi import FastAPI
from routers import snmpv3, ntp, golden_config, aaa

app = FastAPI(
    title="Cisco Micro-Tool Generator API",
    description="Micro-SaaS backend for generating secure Cisco configurations.",
    version="0.2.0"
)

app.include_router(snmpv3.router, prefix="/generate", tags=["SNMPv3"])
app.include_router(ntp.router, prefix="/generate", tags=["NTP"])
app.include_router(golden_config.router, prefix="/generate", tags=["Golden Config"])
app.include_router(aaa.router, prefix="/generate", tags=["AAA / TACACS+"])


@app.get("/")
def root():
    return {
        "status": "ok",
        "message": "Cisco Micro-Tool Generator API is running."
    }
