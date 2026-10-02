# X-Sense Hubitat Integration

Native Hubitat driver for X-Sense smart smoke/CO detectors and water leak sensors via the SBS50 bridge.

## Supported Devices

- **Bridge**: X-Sense SBS50 Base Station
- **Smoke/CO Detectors**: SC07-MR (Smoke + CO Combo) and other Link+ compatible devices
- **Water Leak Sensors**: SWS51 (paired to the SBS50)

## Requirements

- Hubitat Elevation hub (firmware 2.2.4 or later)
- X-Sense SBS50 bridge with detectors configured
- X-Sense account (same credentials used in the X-Sense app)

## Installation

### Option 1: Hubitat Package Manager (Recommended)

1. Open **Hubitat Package Manager** (HPM)
2. Select **Install** → **Search by Keywords**
3. Search for "X-Sense"
4. Select "X-Sense Smoke/CO Detector Integration"
5. Click **Install**
6. Continue to **Setup** section below

### Option 2: Manual Installation

1. In Hubitat, go to **Drivers Code**
2. Click **+ New Driver**
3. Paste the contents of `xsense-hubitat-driver.groovy`
4. Click **Save**
5. Repeat for `xsense-detector-child.groovy` and `xsense-water-child.groovy`

## Setup

1. Go to **Devices** → **Add Device** → **Virtual**
2. Enter a name (e.g., "X-Sense Bridge")
3. Select **X-Sense SBS50 Bridge** as the Type
4. Click **Save Device**
5. In Preferences, enter:
   - **X-Sense Email**: Your X-Sense account email
   - **X-Sense Password**: Your X-Sense account password
   - **Poll Interval**: How often to check for updates (default: 5 minutes)
6. Click **Save Preferences**
7. Click the **Initialize** command button
8. Child devices will be created automatically for each detector

## How It Works

1. The driver authenticates with X-Sense using AWS Cognito SRP (Secure Remote Password)
2. Once authenticated, it fetches your houses, stations (bridges), and devices
3. For each device, a child device is created automatically using the driver that matches its type (smoke/CO detector or water leak sensor)
4. The driver polls the AWS IoT Shadow API for real-time device status

## Child Devices

### Smoke/CO Detectors

Each detector gets its own "X-Sense Smoke/CO Detector" child device with:

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

Each SWS51 gets its own "X-Sense Water Leak Sensor" child device with:

#### Capabilities
- **Water Sensor**: `water` attribute (dry/wet)
- **Battery**: Battery level percentage (0%, 33%, 66%, 100%)

#### Attributes
- `alarmState`: idle/water/muted
- `muteStatus`: muted/notMuted (alarm silenced from the sensor or app)
- `signalStrength`, `rssi`, `healthStatus`, `deviceStatus`, `lastChecked`: same as detectors

### Upgrading from 1.0.x with Water Leak Sensors

Versions before 1.1.0 created every device as a smoke/CO detector. Hubitat does not allow a
parent driver to change a child's driver in place, so after upgrading:

1. Open the bridge device and click **Recreate Child Devices**
2. Any child whose driver does not match its device type is deleted and recreated

Automations that referenced the old child devices will need to be re-pointed at the new ones.

### Diagnosing Unsupported Device Types

If you have an X-Sense device that shows up with the wrong attributes, enable
**Log raw device shadow data on each poll** in the bridge preferences, click **Refresh**, and
copy the `Raw shadow for <serial>` lines from the Hubitat log into a GitHub issue. Turn the
preference back off afterwards, as it logs every device on every poll.

## Integration with Hubitat Safety Monitor

You can use these devices with HSM (Hubitat Safety Monitor):

1. Go to **Apps** → **Hubitat Safety Monitor**
2. Under **Configure** → **Smoke**, select your X-Sense detectors
3. Under **Configure** → **Water**, select your X-Sense water leak sensors

## Polling Interval

This integration polls for device status at a configurable interval:
- **1 minute**: Fastest detection, more API calls
- **5 minutes**: Default, good balance
- **10 minutes**: Reduced API calls
- **30 minutes**: Minimal polling

**Note:** Alarm detection occurs on the next poll cycle, not in real-time. For immediate notification, rely on the physical alarm sound and X-Sense app push notifications.

## Troubleshooting

### "Incorrect username or password" Error
- Verify your X-Sense credentials are correct
- Ensure you're using the email/password for the X-Sense app (not third-party login)

### Devices Not Appearing
- Click **Initialize** after saving credentials
- Check logs for API errors
- Verify devices are configured in the X-Sense app

### Child Devices Not Updating
- Click **Refresh** on the bridge device
- Look for "Polled X device(s)" in logs to confirm polling is working
- Check that the bridge shows "connected" status

### Token Expired Errors
- The driver auto-refreshes tokens
- If persistent, click **Initialize** to re-authenticate

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

## Credits

- Developed with assistance from Claude AI
- API insights from [python-xsense](https://github.com/Jarnsen/python-xsense)

## Disclaimer

This is an unofficial integration not affiliated with or endorsed by X-Sense. Use at your own risk. This should not replace your primary safety notification system.
