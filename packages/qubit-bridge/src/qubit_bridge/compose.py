import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from qubit_bridge.models import BridgeProfile


def render_config(profile: BridgeProfile) -> str:
    """Render the nginx/haproxy config from a BridgeProfile."""
    # We will locate the templates in packages/qubit-bridge/configs
    base_dir = Path(__file__).parent.parent.parent
    configs_dir = base_dir / "configs"
    
    if not configs_dir.exists():
        # Fallback to inline if not set up yet
        if profile.engine == "nginx":
            return f"""
server {{
    listen {profile.listen_port} ssl;
    server_name {profile.server_name};

    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    ssl_protocols TLSv1.3;
    
    # We set the groups for hybrid PQC
    ssl_conf_command Curves {profile.groups};

    location / {{
        proxy_pass http://{profile.upstream};
    }}
}}
"""
        return ""
        
    env = Environment(loader=FileSystemLoader(str(configs_dir)), autoescape=True)
    template_name = "hybrid.conf.j2" if profile.engine == "nginx" else "haproxy.cfg.j2"
    template = env.get_template(template_name)
    
    return template.render(
        listen_port=profile.listen_port,
        server_name=profile.server_name,
        cert_path=profile.cert_path,
        key_path=profile.key_path,
        groups=profile.groups,
        upstream=profile.upstream
    )

def bring_up(profile: BridgeProfile, compose_file: Path) -> None:
    """Render configuration and bring up the container via docker-compose."""
    cfg_text = render_config(profile)
    
    # Write to a generated directory
    gen_dir = Path("generated")
    gen_dir.mkdir(exist_ok=True)
    conf_path = gen_dir / f"{profile.engine}.conf"
    conf_path.write_text(cfg_text)
    
    # Call docker-compose
    cmd = [
        "docker", "compose",
        "-f", str(compose_file),
        "up", "-d", f"{profile.engine}-hybrid"
    ]
    subprocess.run(cmd, check=True)

def tear_down(compose_file: Path) -> None:
    """Tear down the containers."""
    cmd = [
        "docker", "compose",
        "-f", str(compose_file),
        "down"
    ]
    subprocess.run(cmd, check=True)
