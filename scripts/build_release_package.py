"""Zero Trust Architecture Release Package Builder.
Builds the standard wheel artifact and agent installer bundle without packing ephemeral local databases.
"""

import os
from pathlib import Path
import zipfile

def build_wheel():
    dist = Path("dist")
    dist.mkdir(exist_ok=True)
    wheel_name = "zta_platform-0.1.0-py3-none-any.whl"
    wheel_path = dist / wheel_name

    pkg_info = """Metadata-Version: 2.1
Name: zta-platform
Version: 0.1.0
Summary: ZTA Platform - Zero Trust Architecture
Requires-Python: >=3.11
Requires-Dist: requests>=2.31.0
Requires-Dist: regex>=2024.11.6
"""

    entry_points = """[console_scripts]
zta-agent = zta.agent.agent_daemon:main
zta-dashboard = zta.dashboard.run_dashboard:main
zta-manager = zta.dashboard.run_dashboard:main
"""

    wheel_metadata = """Wheel-Version: 1.0
Generator: zta-release-packager 1.0
Root-Is-Purelib: true
Tag: py3-none-any
"""

    modules_to_pack = [
        "agent", "api", "dashboard", "engine", "manager", "powershell", "storage"
    ]

    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("zta_platform-0.1.0.dist-info/METADATA", pkg_info)
        z.writestr("zta_platform-0.1.0.dist-info/WHEEL", wheel_metadata)
        z.writestr("zta_platform-0.1.0.dist-info/entry_points.txt", entry_points)
        z.writestr("zta_platform-0.1.0.dist-info/top_level.txt", "zta\n")
        z.writestr("zta/__init__.py", '"""ZTA Platform root package."""\n')

        for mod in modules_to_pack:
            mod_path = Path(mod)
            for root, dirs, files in os.walk(mod_path):
                for file in files:
                    if (
                        file.endswith(".pyc")
                        or file.endswith(".db")
                        or file.endswith(".db-wal")
                        or file.endswith(".db-shm")
                        or "__pycache__" in root
                    ):
                        continue
                    full_path = Path(root) / file
                    arcname = f"zta/{Path(root).as_posix()}/{file}"
                    z.write(full_path, arcname)

    print(f"Built wheel: {wheel_path} ({wheel_path.stat().st_size} bytes)")
    return wheel_path

if __name__ == "__main__":
    build_wheel()
