# Tor - Terrible onion routing
Pretty self explanatory. It's a tor client that's made in java, since I didn't find many libraries that have the functionality that I'm trying to achieve here.

- This library is still in development and should not be used for production use.

Important ToDos:
- 
- Finish V3 onion services.
- Prevent DESTROY cells from causing unexpected behaviour to the entire client.

The client is also full of println calls since it's mostly the easiest way to debug things, so if you're crazy enough to use it in an actual project, make sure to remove them.