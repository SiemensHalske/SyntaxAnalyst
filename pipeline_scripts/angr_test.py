import angr
import multiprocessing


def symbolic_execution(binary_path, state):
    # Create an Angr project
    project = angr.Project(binary_path, auto_load_libs=False)

    # Create a simulation manager with the given state
    simulation_manager = project.factory.simulation_manager(state)

    # Run symbolic execution
    simulation_manager.run()

    # Collect deadended states and their outputs
    results = []
    if simulation_manager.deadended:
        for state in simulation_manager.deadended:
            output = state.posix.dumps(1)  # 1 represents stdout
            results.append((state.addr, output))
    return results


def main():
    # Path to the binary
    binary_path = "nordstream2.exe"

    # Load the binary into an Angr project
    print(f"Loading binary: {binary_path}")
    project = angr.Project(binary_path, auto_load_libs=False)

    # Create an initial state at the binary's entry point
    initial_state = project.factory.entry_state()

    # Generate multiple states for parallel execution (example: splitting based on program locations)
    states = [initial_state]  # You can customize and create multiple states here.

    # Use multiprocessing to parallelize symbolic execution
    print("Starting parallel symbolic execution...")
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        results = pool.starmap(symbolic_execution, [(binary_path, state) for state in states])

    # Process results
    for result in results:
        for addr, output in result:
            print(f"State address: {hex(addr)}")
            print(f"Console output (symbolic): {output}")


if __name__ == "__main__":
    main()
