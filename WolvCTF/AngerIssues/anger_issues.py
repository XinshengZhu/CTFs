import angr
import claripy
import time

def main():
    print("Starting ANGR solution...")
    start_time = time.time()
    
    # Load the binary
    project = angr.Project("./original", auto_load_libs=False)
    
    # Create symbolic variables for the flag
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(60)]
    flag = claripy.Concat(*flag_chars)
    
    # Create initial state
    state = project.factory.entry_state(stdin=flag)
    
    # Add constraints for printable ASCII
    for c in flag_chars:
        state.solver.add(c >= 32)
        state.solver.add(c <= 126)
    
    # Add constraints for known flag prefix "wctf"
    state.solver.add(flag_chars[0] == ord('w'))
    state.solver.add(flag_chars[1] == ord('c'))
    state.solver.add(flag_chars[2] == ord('t'))
    state.solver.add(flag_chars[3] == ord('f'))
    
    # Create simulation manager
    sim = project.factory.simulation_manager(state)
    
    # Find paths that lead to success and avoid failure
    print("Exploring execution paths (this may take a while)...")
    sim.explore(find=lambda s: b"Yay! You did it!" in s.posix.dumps(1),
                avoid=lambda s: b"Wrong!" in s.posix.dumps(1))
    
    if len(sim.found) > 0:
        # Get the solution state and extract the flag
        solution_state = sim.found[0]
        flag_value = solution_state.posix.dumps(0)
        
        print("\nSolution found!")
        print(f"Flag: {flag_value.decode()}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")
    else:
        print("No solution found.")
    
    return None

if __name__ == "__main__":
    main()

# wctf{1_h0p3_y0u_u53d_ANGR_f0r_th15_0r_y0U_w0uLd_b3_a_duMMy}