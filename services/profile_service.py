import os
import json
from typing import Dict, Any, List

from models.profile_model import DeviceProfile


class ProfileService:
    """
    Handles reading, listing and saving device profiles.
    Profiles are stored as JSON files inside profiles/ directory.
    """

    def __init__(self, profiles_dir: str = "profiles"):
        self.dir = profiles_dir
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, name: str) -> str:
        """Generate full path for profile name."""
        if not name.endswith(".json"):
            name = name + ".json"
        return os.path.join(self.dir, name)

    def list_profiles(self) -> List[str]:
        """Return list of profiles (file names without .json)."""
        files = []
        for f in os.listdir(self.dir):
            if f.endswith(".json"):
                files.append(f.replace(".json", ""))
        return sorted(files)

    def load_profile(self, name: str) -> Dict[str, Any]:
        """Load profile JSON and return dict."""
        path = self._path(name)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Profile '{name}' not found.")

        with open(path, "r") as f:
            return json.load(f)

    def save_profile(self, profile: DeviceProfile) -> None:
        """Save DeviceProfile into JSON."""
        path = self._path(profile.name)

        with open(path, "w") as f:
            json.dump(profile.model_dump(), f, indent=2)

    def delete_profile(self, name: str) -> None:
        """Delete profile file."""
        path = self._path(name)
        if os.path.isfile(path):
            os.remove(path)
