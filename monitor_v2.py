import sys
import curses
import io
import threading
import time
from pathlib import Path
from collections import Counter

# Shared state for tracing
data_lock = threading.Lock()
trace_data = {
    'file': None,
    'lineno': None,
    'locals': {},
    'func_calls': Counter(),
    'output': []
}

# Capture original stdout
original_stdout = sys.stdout
sys.stdout = io.StringIO()

# --- Tracer Function ---
def tracer(frame, event, arg):
    if event not in {'call', 'line'}:
        return tracer

    filename = frame.f_code.co_filename
    lineno = frame.f_lineno
    local_vars = frame.f_locals.copy()
    func_name = frame.f_code.co_name

    with data_lock:
        if event == 'call':
            trace_data['func_calls'][func_name] += 1
        elif event == 'line':
            trace_data['file'] = filename
            trace_data['lineno'] = lineno
            trace_data['locals'] = local_vars.copy()

            # Capture any new output
            output = sys.stdout.getvalue()
            if output:
                trace_data['output'].append((lineno, output))
                sys.stdout.seek(0)
                sys.stdout.truncate(0)
    return tracer

# --- Script Runner ---
def run_script(path):
    sys.settrace(tracer)
    try:
        with open(path) as f:
            code = compile(f.read(), path, 'exec')
            exec(code, {'__name__': '__main__', '__file__': path})
    except Exception as e:
        with data_lock:
            trace_data['output'].append((-1, f"\n[EXCEPTION] {e}\n"))
    finally:
        sys.settrace(None)

# --- Curses UI ---
def curses_main(stdscr, script_path):
    curses.curs_set(0)
    stdscr.nodelay(True)
    max_y, max_x = stdscr.getmaxyx()

    code_win = curses.newwin(max_y, max_x // 2, 0, 0)
    vars_win = curses.newwin(max_y // 3, max_x // 2, 0, max_x // 2)
    funcs_win = curses.newwin(max_y // 3, max_x // 2, max_y // 3, max_x // 2)
    out_win = curses.newwin(max_y - 2 * (max_y // 3), max_x // 2, 2 * (max_y // 3), max_x // 2)

    code_lines = Path(script_path).read_text().splitlines()

    while True:
        stdscr.clear()
        with data_lock:
            lineno = trace_data['lineno']
            var_snapshot = trace_data['locals']
            func_snapshot = trace_data['func_calls']
            output_snapshot = trace_data['output'][-10:]  # last 10 outputs

        # Code Pane
        code_win.erase()
        max_y, max_x = code_win.getmaxyx()
        for idx, line in enumerate(code_lines[:max_y - 2]):
            trimmed_line = line[:max_x - 4]  # leave space for '=> '
            prefix = "=> " if idx + 1 == lineno else "   "
            try:
                code_win.addstr(idx + 1, 1, prefix + trimmed_line, curses.A_REVERSE if idx + 1 == lineno else 0)
            except curses.error:
                pass  # Avoid crash on edge overflow
        code_win.box()
        code_win.addstr(0, 2, " Code View ")

        # Variables Pane
        vars_win.erase()
        max_vars_y, max_vars_x = vars_win.getmaxyx()
        for idx, (k, v) in enumerate(var_snapshot.items()):
            if idx >= max_vars_y - 2:
                break  # prevent overflow
            try:
                value_str = f"{k} = {v}"
                vars_win.addstr(idx + 1, 1, value_str[:max_vars_x - 2])
            except curses.error:
                pass  # silently ignore if even cropped line doesn't fit

        vars_win.box()
        vars_win.addstr(0, 2, " Variables ")

        # Functions Pane
        funcs_win.erase()
        max_y, max_x = funcs_win.getmaxyx()
        for idx, (fn, count) in enumerate(func_snapshot.items()):
            if idx >= max_y - 2:
                break  # don’t write past bottom
            try:
                line = f"{fn}() called {count}x"
                funcs_win.addstr(idx + 1, 1, line[:max_x - 2])
            except curses.error:
                pass  # silently ignore crashy lines

        funcs_win.box()
        funcs_win.addstr(0, 2, " Functions ")

        # Output Pane
        out_win.erase()
        for idx, (line_num, txt) in enumerate(output_snapshot):
            txt_lines = txt.strip().splitlines()
            for sub_idx, subline in enumerate(txt_lines):
                if idx * 2 + sub_idx < out_win.getmaxyx()[0] - 2:
                    out_win.addstr(idx * 2 + sub_idx + 1, 1, f"[L{line_num}] {subline}")
        out_win.box()
        out_win.addstr(0, 2, " Output ")

        stdscr.refresh()
        code_win.refresh()
        vars_win.refresh()
        funcs_win.refresh()
        out_win.refresh()

        time.sleep(0.3)
        if not script_thread.is_alive():
            stdscr.addstr(1, 2, "Script finished. Press any key to exit...")
            stdscr.refresh()
            stdscr.getch()
            break

# --- Main Entry ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debugger.py your_script.py")
        sys.exit(1)

    script_path = sys.argv[1]
    script_thread = threading.Thread(target=run_script, args=(script_path,))
    script_thread.start()
    curses.wrapper(curses_main, script_path)
    script_thread.join()

    # Print any final output captured
    final_out = sys.stdout.getvalue()
    if final_out:
        print("\n--- Final Output ---")
        print(final_out)

    # Restore stdout
    sys.stdout = original_stdout

