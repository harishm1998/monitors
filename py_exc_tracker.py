# trace_runner.py
import sys

def trace_lines(frame, event, arg):
    if event == "line":
        lineno = frame.f_lineno
        filename = frame.f_globals.get("__file__", None)
        if filename and filename.endswith(".py"):
            try:
                with open(filename) as f:
                    lines = f.readlines()
                print(f"[{filename}:{lineno}] {lines[lineno - 1].strip()}")
            except Exception as e:
                print(f"[Error reading line {lineno} in {filename}]: {e}")
    return trace_lines

def main(script_path):
    sys.settrace(trace_lines)
    with open(script_path) as f:
        code = compile(f.read(), script_path, 'exec')
        exec(code, {'__name__': '__main__', '__file__': script_path})

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python trace_runner.py your_script.py")
        sys.exit(1)
    main(sys.argv[1])
