# X-Sense Hubitat Integration

Native Hubitat integration for X-Sense smart smoke/CO detectors and water leak sensors connected
through the SBS50 base station. Installed as a Hubitat app that creates one child device per sensor.

## Supported Devices

- **Base station**: X-Sense SBS50
- **Smoke/CO Detectors**: SC07-MR (Smoke + CO Combo) and other Link+ compatible devices
- **Water Leak Sensors**: SWS51 (paired to the SBS50)

## Requirements

- Hubitat Elevation hub (firmware 2.2.4 or later)
- X-Sense SBS50 base station with sensors configured in the X-Sense app
- X-Sense account (the same email and password you use in the X-Sense app)

## Installation

### Option 1: Hubitat Package Manager (Recommended)

1. Open **Hubitat Package Manager** (HPM)
2. Select **Install** → **Search by Keywords**
3. Search for "X-Sense"
4. Select "X-Sense Integration"
5. Click **Install**. HPM installs the app and both child drivers.
6. Continue to **Setup** below

### Option 2: Manual Installation

1. In Hubitat, go to **Apps Code** → **+ New App**, paste `xsense-app.groovy`, click **Save**
2. Go to **Drivers Code** → **+ New Driver**, paste `xsense-detector-child.groovy`, click **Save**
3. Repeat for `xsense-water-child.groovy`

## Setup

1. Go to **Apps** → **Add User App**
2. Select **X-Sense Integration**
3. Enter your **X-Sense Email** and **X-Sense Password**
4. Choose a **Poll Interval** (default 5 minutes)
5. Click **Done**

The app logs in, discovers your houses, base stations, and sensors, and creates a child device for
each sensor. Reopen the app to see connection status, counts, the last error if any, and a table of
devices with links to each one.

### App Page Actions

- **Log In and Discover Devices**: re-authenticate and re-run discovery
- **Refresh Device Status**: poll the X-Sense cloud now
- **Recreate Child Devices**: delete any child whose driver does not match its device type and recreate it

Actions run in the background. Refresh the app page after a few seconds to see the result.

## How It Works

1. The app authenticates with X-Sense using AWS Cognito SRP (Secure Remote Password)
2. Once authenticated, it fetches your houses, stations (base stations), and devices
3. For each device, a child device is created using the driver that matches its type
4. The app polls the AWS IoT Shadow API for device status at the configured interval

## Child Devices

### Smoke/CO Detectors

Each detector gets an "X-Sense Smoke/CO Detector" child device with:

#### Capabilities
- **Smoke Detector**: `smoke` attribute (clear/detected)
- **Carbon Monoxide Detector**: `carbonMonoxide` attribute (clear/detected)
- **Battery**: Battery level percentage (0%, 33%, 66%, 100%)
- **Temperature** (if supported by device)
- **Humidity** (if supported by device)

#### Attributes
- `carbonMonoxideLevel`: CO level in PPM
- `alarmState`: Current alarm state (idle/smoke/carbonMonoxide/muted)
- `signalStrength`: Connection quality (excellent/good/fair/poor)
- `rssi`: Signal strength in dBm
- `healthStatus`: online/offline
- `deviceStatus`: Online/offline status
- `lastChecked`: Timestamp of last status update

#### Commands
- **Refresh**: Request immediate status update

### Water Leak Sensors

Each SWS51 gets an "X-Sense Water Leak Sensor" child device with:

#### Capabilities
- **Water Sensor**: `water` attribute (dry/wet)
- **Battery**: Battery level percentage (0%, 33%, 66%, 100%)

#### Attributes
- `alarmState`: idle/water/muted
- `muteStatus`: muted/notMuted (alarm silenced from the sensor or app)
- `signalStrength`, `rssi`, `healthStatus`, `deviceStatus`, `lastChecked`: same as detectors

## Integration with Hubitat Safety Monitor

1. Go to **Apps** → **Hubitat Safety Monitor**
2. Under **Configure** → **Smoke**, select your X-Sense detectors
3. Under **Configure** → **Water**, select your X-Sense water leak sensors

## Upgrading from 1.x

Version 1.x was a virtual "X-Sense SBS50 Bridge" device. Version 2.0 is an app, so it is a different
package rather than an update. Do not use **Update** in HPM. Uninstall the old package and install the
new one:

1. In **Devices**, open your old **X-Sense Bridge** device and click **Remove Device**. This also
   removes its child devices.
2. In **Hubitat Package Manager**, choose **Uninstall** and remove the old X-Sense package. If HPM
   reports an error because something was already deleted by hand, choose **Package Manager
   Settings** → **Un-Match a Package** instead, then delete any leftover X-Sense entries from
   **Apps Code** and **Drivers Code**.
3. In HPM, choose **Install** → **Search by Keywords** → "X-Sense" and install **X-Sense Integration**.
4. Follow **Setup** above. New child devices are created for every sensor.
5. Re-point rules, dashboard tiles, and Hubitat Safety Monitor entries at the new child devices.

**Tip:** always add and remove this package through HPM. Deleting app or driver code by hand from
Apps Code or Drivers Code leaves HPM with a stale record, and its Update, Repair, and Uninstall
actions will fail until you use Un-Match a Package.

## Polling Interval

- **1 minute**: Fastest detection, more API calls
- **5 minutes**: Default, good balance
- **10 minutes**: Reduced API calls
- **30 minutes**: Minimal polling

**Note:** Alarm detection occurs on the next poll cycle, not in real-time. For immediate notification,
rely on the physical alarm sound and X-Sense app push notifications.

## Troubleshooting

### "Incorrect username or password" Error
- Verify your X-Sense credentials are correct
- Ensure you're using the email/password for the X-Sense app (not third-party login)

### Devices Not Appearing
- Open the app and click **Log In and Discover Devices**
- Check the **Last error** line on the app page and the Hubitat log
- Verify devices are configured in the X-Sense app

### Child Devices Not Updating
- Open the app and click **Refresh Device Status**
- Look for "Polled X device(s)" in the Hubitat log
- Check that the app page shows Connection: connected

### Wrong Driver on a Device
- Open the app and click **Recreate Child Devices**

### Diagnosing Unsupported Device Types

If an X-Sense device shows up with the wrong attributes, enable **Log raw device shadow data on each
poll** in the app, click **Refresh Device Status**, and copy the `Raw shadow for <serial>` lines from
the Hubitat log into a GitHub issue. Turn the option back off afterwards, as it logs every device on
every poll.

## Technical Details

### Authentication Flow
1. **Get Client Info** (101001): Retrieves Cognito pool ID and client credentials
2. **SRP Auth**: Performs AWS Cognito USER_SRP_AUTH flow
3. **Get AWS Tokens** (101003): Obtains temporary AWS IoT credentials
4. **Discover Devices**: Fetches houses (102007) and stations (103007)
5. **Shadow API**: Polls AWS IoT Shadow for device status

### APIs Used
- X-Sense API: `https://api.x-sense-iot.com`
- AWS Cognito: SRP authentication
- AWS IoT Shadow: Device status via `{region}.x-sense-iot.com`

## Known Limitations

- **Cloud-dependent**: Requires internet connection and X-Sense cloud
- **Polling only**: Status updates occur at configured interval, not real-time push
- **Read-only**: Cannot trigger test alarms or control devices remotely

## License

Apache License 2.0
