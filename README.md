# SYSC3303A W26 A2 Grading Script Instructions

## Requirements

- Python 3.8+
- JDK with `javac` and `java` on your `PATH`

## Running the Script

From the `grade_script` directory, pass the path to the submission as the first argument.

### Linux / macOS

```bash
./grade_a2.sh /path/to/submission
```

### Windows (PowerShell)

```powershell
.\grade_a2.ps1 \path\to\submission
```

### Directly with Python

```bash
python3 grade_a2.py --root /path/to/submission
```

If no path is provided, the current directory is used as the submission root.

## Overriding Main Class Names

If the script cannot auto-detect `Client`, `IntermediateHost`, or `Server`, set these environment variables before running:

### Linux / macOS

```bash
MAIN_SERVER=MyServer MAIN_HOST=MyHost MAIN_CLIENT=MyClient ./grade_a2.sh .
```

### Windows (PowerShell)

```powershell
$env:MAIN_SERVER="MyServer"
$env:MAIN_HOST="MyHost"
$env:MAIN_CLIENT="MyClient"
.\grade_a2.ps1 .
```

## What It Checks

1. Diagrams: looks for a class diagram and sequence diagram by filename.
2. Code Quality: JavaDoc, comment density, method length, source files present.
3. Compilation: compiles all `.java` files with `javac`.
4. End-to-End: runs `Server`, `IntermediateHost`, and `Client`; tests `JOIN`, `MOVE`, `PICKUP`, `STATE`, and a second concurrent client.

Logs are saved to `.a2_logs/` inside the submission directory.
