import os, re, sys
from pathlib import Path

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'get':
        env_file = Path(__file__).resolve().parent.parent / '.env'
        if env_file.exists():
            content = env_file.read_text(encoding='utf-8')
            m = re.search(r'^GITHUB_TOKEN=(.+)$', content, re.MULTILINE)
            if m:
                token = m.group(1).strip()
                print('username=x-access-token')
                print(f'password={token}')

if __name__ == '__main__':
    main()
