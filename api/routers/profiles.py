from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from services.profile_service import ProfileService
from models.profile_model import DeviceProfile

router = APIRouter()
svc = ProfileService()


# List profiles
@router.get("/profiles/list")
def list_profiles():
    return {"profiles": svc.list_profiles()}


# Load profile
@router.get("/profiles/load/{name}")
def load_profile(name: str):
    try:
        data = svc.load_profile(name)
        return data
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Profile not found")


# Save profile
@router.post("/profiles/save")
def save_profile(profile: DeviceProfile):
    svc.save_profile(profile)
    return {"status": "ok", "saved_as": profile.name}


# Delete profile
@router.delete("/profiles/delete/{name}")
def delete_profile(name: str):
    try:
        svc.delete_profile(name)
        return {"status": "deleted", "name": name}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Profile not found")
