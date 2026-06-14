import atexit
import base64
import contextlib
import tempfile
import json
import logging
import os
import secrets
import signal
import subprocess
import threading
import time
from urllib import error, request


DEFAULT_JOERN_JAVA_OPTS = "-Xms1g -XX:InitialRAMPercentage=10.0 -XX:MaxRAMPercentage=80.0"


def _get_astrail_config() -> dict:
    from config_provider import ConfigProvider

    config = ConfigProvider.get_config()
    return (config.tools or {}).get("astrail", {})


class AstrailServer:
    """Manage the Astrail HTTP server lifecycle for the modular runtime."""

    def __init__(self):
        self.__cpg_path = None
        self.__server_process = None
        self.__port = _get_astrail_config().get("port", 9001)
        self.__registered_cleanup = False
        self.__log_file = None
        self.__auth_username = None
        self.__auth_password = None

    def get_auth(self) -> tuple[str, str] | None:
        if self.__auth_username and self.__auth_password:
            return (self.__auth_username, self.__auth_password)
        return None

    def _auth_header(self) -> dict:
        auth = self.get_auth()
        if not auth:
            return {}
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def _build_log_file_path(self, port: int) -> str:
        return os.path.join(tempfile.gettempdir(), f"crt-astrail-server-{port}.log")

    def set_cpg_path(self, cpg_path: str):
        self.__cpg_path = cpg_path

    def _get_connect_host(self) -> str:
        host = _get_astrail_config().get("host", "127.0.0.1")
        return "127.0.0.1" if host == "0.0.0.0" else host

    def get_query_sync_url(self) -> str:
        return f"http://{self._get_connect_host()}:{self.__port}/query-sync"

    def is_running(self) -> bool:
        return self.__server_process is not None and self.__server_process.poll() is None

    def start(self, port: int):
        if self.is_running():
            logging.info("[astrail] Server already running")
            return

        astrail_cfg = _get_astrail_config()
        astrail_path = astrail_cfg.get("astrailpath")
        if not astrail_path:
            raise RuntimeError("config.tools.astrail.astrailpath is not set")
        if not os.path.exists(astrail_path):
            raise FileNotFoundError(f"astrail executable not found at: {astrail_path}")

        if not self.__cpg_path:
            raise RuntimeError("CPG path not set; call set_cpg_path(path) before start()")
        if not os.path.exists(self.__cpg_path):
            raise FileNotFoundError(f"CPG path does not exist: {self.__cpg_path}")

        env = os.environ.copy()
        env.setdefault("JAVA_OPTS", DEFAULT_JOERN_JAVA_OPTS)

        self.__port = port
        self.__log_file = self._build_log_file_path(port)

        bind_host = self._get_connect_host()
        self.__auth_username = "nika"
        self.__auth_password = secrets.token_urlsafe(32)

        cmd = [
            astrail_path,
            "--server",
            "--server-host",
            bind_host,
            "--server-port",
            str(port),
            "--server-auth-username",
            self.__auth_username,
            "--server-auth-password",
            self.__auth_password,
        ]

        redacted = ["***" if token == self.__auth_password else token for token in cmd]
        logging.info(f"[astrail] Starting HTTP server: {' '.join(redacted)}")
        with open(self.__log_file, "ab") as log_handle:
            self.__server_process = subprocess.Popen(
                cmd,
                env=env,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        if not self.__registered_cleanup:
            atexit.register(self.stop)
            self.__registered_cleanup = True

        if not self._wait_for_server(timeout=60):
            log_hint = f" See {self.__log_file} for details." if self.__log_file else ""
            if self.has_exited():
                exit_code = self.exit_code()
                self._stop(remove_log=False)
                raise RuntimeError(
                    f"Astrail server failed to start. Exit code: {exit_code}.{log_hint}"
                )
            self._stop(remove_log=False)
            raise RuntimeError(f"Astrail server did not become ready before timeout.{log_hint}")

        if self.has_exited():
            raise RuntimeError(
                f"Astrail server failed to start. Exit code: {self.exit_code()}. "
                f"Check {self.__log_file} for details."
            )

        logging.info(
            f"[astrail] HTTP server running at http://{self._get_connect_host()}:{port} "
            f"(PID: {self.__server_process.pid})"
        )

    def _wait_for_server(self, timeout: int = 60):
        start_time = time.time()
        payload = json.dumps({"query": "1"}).encode("utf-8")
        url = self.get_query_sync_url()

        while time.time() - start_time < timeout:
            if self.__server_process.poll() is not None:
                return False

            try:
                req = request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json", **self._auth_header()},
                    method="POST",
                )
                with request.urlopen(req, timeout=2) as response:
                    if response.status == 200:
                        logging.info(f"[astrail] query-sync is ready on port {self.__port}.")
                        return True
            except error.HTTPError:
                time.sleep(2)
            except error.URLError:
                time.sleep(2)
            except ConnectionResetError:
                time.sleep(2)
            except TimeoutError:
                time.sleep(2)

        logging.warning("[astrail] Timed out waiting for query-sync to become ready.")
        return False

    def has_exited(self) -> bool:
        return self.__server_process is not None and self.__server_process.poll() is not None

    def exit_code(self) -> int | None:
        if self.__server_process is None:
            return None
        return self.__server_process.poll()

    def stop(self):
        self._stop(remove_log=True)

    def _stop(self, remove_log: bool):
        if self.__server_process is None:
            return

        if self.__server_process.poll() is None:
            logging.info(f"[astrail] Stopping server (PID: {self.__server_process.pid})...")
            try:
                pgid = os.getpgid(self.__server_process.pid)
                os.killpg(pgid, signal.SIGTERM)

                try:
                    self.__server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.info("[astrail] Server didn't stop gracefully, force killing...")
                    os.killpg(pgid, signal.SIGKILL)
                    self.__server_process.wait()
            except ProcessLookupError:
                logging.info("[astrail] Process already terminated")
            except Exception as exc:
                logging.info(f"[astrail] Error stopping server: {exc}")
                with contextlib.suppress(Exception):
                    self.__server_process.kill()
                    self.__server_process.wait()

        self.__server_process = None
        self.__cpg_path = None
        self.__auth_username = None
        self.__auth_password = None
        if remove_log and self.__log_file and os.path.exists(self.__log_file):
            with contextlib.suppress(OSError):
                os.remove(self.__log_file)
        logging.info("[astrail] Server stopped")

    def get_server_url(self) -> str | None:
        if not self.is_running():
            return None
        return f"http://{self._get_connect_host()}:{self.__port}"


_astrail_server_instance = None
_astrail_server_lock = threading.Lock()


def get_astrail_server() -> AstrailServer:
    global _astrail_server_instance
    with _astrail_server_lock:
        if _astrail_server_instance is None:
            _astrail_server_instance = AstrailServer()
        return _astrail_server_instance


__all__ = ["AstrailServer", "get_astrail_server"]
