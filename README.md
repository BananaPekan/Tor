# Tor - Terrible onion routing
Pretty self explanatory. It's a tor client that's made in java, since I didn't find many libraries that have the functionality that I'm trying to achieve here.

- This library is still in development and should not be used for production use.

Important ToDos:
- 
- Finish V3 onion services.
- Prevent DESTROY cells from causing unexpected behaviour to the entire client.

**NOTE: At the moment (And probably even when the project is finished, also to a lesser extent) the client does NOT completely conform to the tor spec.**
For this exact reason, it should not be used in actual projects, at least at the moment, even for connecting to regular services (Not HS), and probably not securely to HSs when it's finished.

The client is also full of println calls since it's mostly the easiest way to debug things, so if you're crazy enough to use it in an actual project, make sure to remove them.

Known issues:
-
- DESTROY cells may cause unexpected behaviour.
- There is no tearing down mechanism for circuits, which may result in the client getting stuck when trying to connect to an OR and silently failing, leaving the program hanging.

Usage example (as of right now):

```java
// Open a connection to a new directory and fetch a consensus
Directory directory = new Directory(dirHost, orPort);
directory.fetchConsensus();
// Pick a random guard and create a circuit
Guard guard = new Guard(directory.pickRandomGuard());
guard.connect();
guard.initialHandshake();
Circuit circuit = guard.create2();
// Extend the circuit by 2 hops
circuit.extend(directory.pickRandomRelay());
circuit.extend(directory.pickRandomExit());
// Create a stream to a certain destination
Stream stream = circuit.createNewStream(targetHost, targetPort);
// Do something with the stream (send/receive data)
...
```