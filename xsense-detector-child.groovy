/**
 *  X-Sense Smoke/CO Detector Child Driver for Hubitat
 *
 *  Copyright 2025
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Description:
 *  Child driver for X-Sense smoke and CO detectors (SC07-MR and compatible models).
 *  Works in conjunction with the X-Sense SBS50 Bridge parent driver.
 */

metadata {
    definition(name: "X-Sense Smoke/CO Detector", namespace: "xsense", author: "Community") {
        capability "Smoke Detector"
        capability "Carbon Monoxide Detector"
        capability "Battery"
        capability "Sensor"
        capability "Refresh"
        capability "Temperature Measurement"
        capability "Relative Humidity Measurement"

        attribute "lastChecked", "string"
        attribute "deviceStatus", "string"
        attribute "signalStrength", "string"
        attribute "rssi", "number"
        attribute "serialNumber", "string"
        attribute "firmwareVersion", "string"
        attribute "deviceType", "string"
        attribute "alarmState", "string"
        attribute "mutedUntil", "string"
        attribute "selfTestResult", "string"
        attribute "healthStatus", "string"
        attribute "carbonMonoxideLevel", "number"

        command "testAlarm"
        command "muteAlarm", [[name: "minutes", type: "NUMBER", description: "Minutes to mute (1-60)"]]
        command "unmuteAlarm"
    }

    preferences {
        input name: "enableDebug", type: "bool", title: "Enable Debug Logging", defaultValue: false
    }
}

// ==================== Lifecycle Methods ====================

def installed() {
    logDebug "X-Sense Detector child device installed"
    initialize()
}

def updated() {
    logDebug "X-Sense Detector child device updated"
}

def initialize() {
    sendEvent(name: "smoke", value: "clear")
    sendEvent(name: "carbonMonoxide", value: "clear")
    sendEvent(name: "alarmState", value: "idle")
    sendEvent(name: "deviceStatus", value: "unknown")
}

// ==================== Capability Commands ====================

def refresh() {
    logDebug "Refresh requested"
    // Ask parent to refresh
    parent?.refresh()
}

def testAlarm() {
    logDebug "Test alarm requested"
    def serialNumber = device.getDataValue("serialNumber")
    if (serialNumber) {
        parent?.testAlarm(serialNumber)
    } else {
        log.warn "Cannot test alarm - no serial number"
    }
}

def muteAlarm(minutes) {
    logDebug "Mute alarm for ${minutes} minutes"
    def mutedUntil = new Date(now() + (minutes * 60 * 1000)).format("yyyy-MM-dd HH:mm:ss")
    sendEvent(name: "mutedUntil", value: mutedUntil)
    sendEvent(name: "alarmState", value: "muted")
    runIn(minutes * 60, "unmuteAlarm")
}

def unmuteAlarm() {
    logDebug "Unmute alarm"
    sendEvent(name: "mutedUntil", value: "")
    sendEvent(name: "alarmState", value: "idle")
}

// ==================== Update Methods (called by parent) ====================

def updateStatus(Map status) {
    logDebug "Updating status: ${status}"

    // Smoke status
    if (status.containsKey("smoke")) {
        def smokeVal = status.smoke == 1 || status.smoke == true ? "detected" : "clear"
        sendEvent(name: "smoke", value: smokeVal)
        if (smokeVal == "detected") {
            sendEvent(name: "alarmState", value: "smoke")
        }
    }

    // CO status
    if (status.containsKey("co")) {
        def coVal = status.co == 1 || status.co == true ? "detected" : "clear"
        sendEvent(name: "carbonMonoxide", value: coVal)
        if (coVal == "detected") {
            sendEvent(name: "alarmState", value: "carbonMonoxide")
        }
    }

    // Battery level
    if (status.containsKey("battery")) {
        sendEvent(name: "battery", value: status.battery, unit: "%")
    }

    // Temperature (if supported)
    if (status.containsKey("temperature")) {
        sendEvent(name: "temperature", value: status.temperature, unit: "°F")
    }

    // Humidity (if supported)
    if (status.containsKey("humidity")) {
        sendEvent(name: "humidity", value: status.humidity, unit: "%")
    }

    // Signal strength
    if (status.containsKey("rssi") || status.containsKey("signal")) {
        def signal = status.rssi ?: status.signal
        def signalStr = "unknown"
        if (signal >= -50) signalStr = "excellent"
        else if (signal >= -60) signalStr = "good"
        else if (signal >= -70) signalStr = "fair"
        else signalStr = "poor"
        sendEvent(name: "signalStrength", value: signalStr)
    }

    // Device online status
    if (status.containsKey("online")) {
        sendEvent(name: "deviceStatus", value: status.online ? "online" : "offline")
    }

    // Reset alarm state if all clear
    if (device.currentValue("smoke") == "clear" &&
        device.currentValue("carbonMonoxide") == "clear" &&
        device.currentValue("alarmState") != "muted") {
        sendEvent(name: "alarmState", value: "idle")
    }

    sendEvent(name: "lastChecked", value: new Date().format("yyyy-MM-dd HH:mm:ss"))
}

def setDeviceInfo(Map info) {
    logDebug "Setting device info: ${info}"

    if (info.serialNumber) {
        device.updateDataValue("serialNumber", info.serialNumber)
        sendEvent(name: "serialNumber", value: info.serialNumber)
    }

    if (info.firmwareVersion) {
        device.updateDataValue("firmwareVersion", info.firmwareVersion)
        sendEvent(name: "firmwareVersion", value: info.firmwareVersion)
    }

    if (info.deviceType) {
        device.updateDataValue("deviceType", info.deviceType)
        sendEvent(name: "deviceType", value: info.deviceType)
    }
}

def setSelfTestResult(String result) {
    sendEvent(name: "selfTestResult", value: result)
}

// ==================== Logging ====================

def logDebug(msg) {
    if (enableDebug) log.debug "[X-Sense Detector] ${msg}"
}
