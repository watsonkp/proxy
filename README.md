# Proxy

A proxy capable of parsing, intercepting, editing, and sending traffic from an ever expanding list of protocols including HTTP and TLS. This tool can be used through a text-based user interface (TUI) or programmatically through a Rust API.

This project is motivated by a desire to dig into the messy world of implementing network protocols, valuing clear and usable tools that don't obfuscate data or functionality, and gaining experience with Rust.

## Progress
The project description may sound nice, but it doesn't describe the current rudimentary project state. There is a lot of work to be done, but that's the point.

Version numbers signify progress. Version 1.0 will be a limited but functional proof of concept fulfilling the project description.

### Near Term Development Tasks
* [ ] Initial TUI implementation.
* [ ] Editing and sending captured requests.
* [ ] Parsing incoming HTTP (version < 2) requests.
