Note: You must be running OpenJDK. Bouncy Castle's PGP library has dependencies that Oracle's JDK does not provide.

This example is specific to OpenJDK 1.6. This is not an Invoked Dynamic bug.

Clone this repo and run `./runner.rb`

In JRuby 1.6.x, it will encrypt / decrypt successfully.
In JRuby 1.7.0 preview, it will blow up with a backtrace.
