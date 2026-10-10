#!/usr/bin/env python3
"""Build and run portable UART bridge tests with a host C++ compiler."""

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nanopb-dir", type=Path, help="Directory containing pb.h")
    args = parser.parse_args()
    nanopb = args.nanopb_dir
    if not nanopb:
        nanopb = next((root / ".pio/libdeps").glob("*/Nanopb"), None)
    if not nanopb or not (nanopb / "pb.h").is_file():
        parser.error(
            "Provide --nanopb-dir or install a firmware build's Nanopb dependency"
        )

    env = os.environ.copy()
    compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    if not compiler and os.name == "nt":
        vswhere = (
            Path(os.environ["ProgramFiles(x86)"])
            / "Microsoft Visual Studio/Installer/vswhere.exe"
        )
        installation = subprocess.check_output(
            [
                str(vswhere),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
            ],
            text=True,
        ).strip()
        vcvars = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
        output = subprocess.check_output(
            f'cmd.exe /d /s /c ""{vcvars}" >nul && set"', text=True
        )
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator and key:
                env[key] = value
        compiler = shutil.which("cl.exe", path=env.get("Path", env.get("PATH")))
    if not compiler:
        parser.error(
            "Install a host C++ compiler (GCC, Clang or Visual Studio C++ tools)"
        )

    includes = [root / "src", root / "src/mesh/generated", nanopb.resolve()]
    source = root / "test/test_uart_bridge/test_protocol.cpp"
    with tempfile.TemporaryDirectory(prefix="meshtastic-uart-bridge-") as temp:
        executable = Path(temp) / ("test.exe" if os.name == "nt" else "test")
        if Path(compiler).name.lower() == "cl.exe":
            command = [compiler, "/nologo", "/std:c++17", "/EHsc", "/W4"]
            command += [f"/I{path}" for path in includes] + [
                str(source),
                f"/Fe:{executable}",
            ]
        else:
            command = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror"]
            command += [f"-I{path}" for path in includes] + [
                str(source),
                "-o",
                str(executable),
            ]
        define = "/D" if Path(compiler).name.lower() == "cl.exe" else "-D"
        command += [
            str(root / "src/mesh/generated/meshtastic" / name)
            for name in (
                "mesh.pb.cpp",
                "channel.pb.cpp",
                "config.pb.cpp",
                "device_ui.pb.cpp",
                "module_config.pb.cpp",
                "telemetry.pb.cpp",
                "xmodem.pb.cpp",
            )
        ]
        command += [
            str(nanopb.resolve() / name)
            for name in ("pb_common.c", "pb_encode.c", "pb_decode.c")
        ]
        command.append(f"{define}UART_BRIDGE_HOST_TEST=1")
        for full in (False, True):
            build = command + ([f"{define}UART_BRIDGE_FULL=1"] if full else [])
            subprocess.run(build, cwd=temp, env=env, check=True)
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
