import sys
import os
import subprocess

def main():
    if len(sys.argv) < 4:
        print("Usage: python create_and_commit.py <file_path> <commit_message> <content_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    commit_message = sys.argv[2]
    content_file = sys.argv[3]

    with open(content_file, 'r') as f:
        content = f.read()

    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    with open(file_path, 'w') as f:
        f.write(content)

    subprocess.run(['git', 'add', file_path], check=True)
    subprocess.run(['git', 'commit', '-m', f"Add {os.path.basename(file_path)}: {commit_message}"], check=True)

if __name__ == "__main__":
    main()
