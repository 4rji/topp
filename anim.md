Implement an animated network traffic visualization using a **Data Packet Flow** effect.

**Visual design:**
- Represent network connections as thin, dark-red lines resembling Ethernet cables.
- Animate glowing red data packets traveling along each connection.
- Use variable packet lengths, irregular spacing, and different travel speeds.
- Give each packet a bright leading edge and a fading gradient trail.
- Add a subtle red neon glow without excessive brightness.
- Use a dark background for contrast, inspired by Opengear's red color scheme.

**Animation behavior:**
- Continuous, smooth, directional movement.
- Independent animation timing for each connection.
- Support bidirectional traffic.
- Adjust packet frequency based on actual network traffic volume when telemetry is available.
- Idle connections should remain dim and stationary.
- Avoid blinking, breathing, or synchronized animations.

**Implementation:**
- Build it as a reusable, configurable component.
- Expose parameters for color, speed, direction, packet size, traffic density, and glow intensity.
- Optimize rendering for multiple simultaneous connections.
- Follow the application's existing framework and architecture.

The result should resemble live network packets flowing through physical cables, rather than decorative LED animations.