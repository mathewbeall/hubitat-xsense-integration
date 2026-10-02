/**
 *  X-Sense Water Leak Sensor Child Driver for Hubitat
 *
 *  Copyright 2025
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Description:
 *  Child driver for X-Sense water leak sensors (SWS51 and compatible models).
 *  Works in conjunction with the X-Sense SBS50 Bridge parent driver.
 *
 *  The parent driver creates this child for any device whose X-Sense type begins with "SWS".
 *  Status comes from the base station shadow: waterAlarmStatus (0 = dry, 1 = wet) and
 *  waterMuteStatus (0 = not muted, 1 = muted).
 */

metadata {
    definition(name: "X-Sense Water Leak Sensor", namespace: "xsense", author: "Community") {
        capability "Water Sensor"
        capability "Battery"
        capability "Sensor"
        capability "Refresh"

        attribute "lastChecked", "string"
        attribute "deviceStatus", "string"
        attribute "healthStatus", "string"
        attribute "signalStrength", "string"
        attribute "rssi", "number"
        attribute "serialNumber", "string"
        attribute "firmwareVersion", "string"
        attribute "deviceType", "string"
        attribute "alarmState", "string"   // idle / water / muted
        attribute "muteStatus", "string"   // muted / notMuted
    }

    preferences {
        input name: "enableDebug", type: "bool", title: "Enable Debug Logging", defaultValue: false
    }
}

// ==================== Lifecycle Methods ====================

def installed() {
    logDebug "X-Sense Water Leak Sensor child device installed"
    initialize()
}

def updated() {
    logDebug "X-Sense Water Leak Sensor child device updated"
}

def initialize() {
    sendEvent(name: "water", value: "dry")
    sendEvent(name: "alarmState", value: "idle")
    sendEvent(name: "muteStatus", value: "notMuted")
    sendEvent(name: "deviceStatus", value: "unknown")
}

// ==================== Capability Commands ====================

def refresh() {
    logDebug "Refresh requested"
    parent?.refresh()
}

// ==================== Update Methods (called by parent) ====================

/**
 * Accepts a normalized status map from the parent:
 *   water:   true/1 = wet, false/0 = dry
 *   muted:   true/1 = alarm muted
 *   battery: percentage
 *   rssi:    dBm
 *   online:  true/false
 */
def updateStatus(Map status) {
    logDebug "Updating status: ${status}"

    if (status.containsKey("water")) {
        def wet = (status.water == 1 || status.water == true || status.water == "1")
        sendEvent(name: "water", value: wet ? "wet" : "dry")
    }

    if (status.containsKey("muted")) {
        def muted = (status.muted == 1 || status.muted == true || status.muted == "1")
        sendEvent(name: "muteStatus", value: muted ? "muted" : "notMuted")
    }

    if (status.containsKey("battery")) {
        sendEvent(name: "battery", value: status.battery, unit: "%")
    }

    if (status.containsKey("rssi")) {
        def rssi = status.rssi as Integer
        sendEvent(name: "rssi", value: rssi, unit: "dBm")
        def signalStr = "unknown"
        if (rssi >= -50) signalStr = "excellent"
        else if (rssi >= -60) signalStr = "good"
        else if (rssi >= -70) signalStr = "fair"
        else signalStr = "poor"
        sendEvent(name: "signalStrength", value: signalStr)
    }

    if (status.containsKey("online")) {
        def onlineStr = status.online ? "online" : "offline"
        sendEvent(name: "healthStatus", value: onlineStr)
        sendEvent(name: "deviceStatus", value: onlineStr)
    }

    // Derive alarmState from water + mute
    def water = device.currentValue("water")
    def muted = device.currentValue("muteStatus") == "muted"
    def alarmState = "idle"
    if (water == "wet") {
        alarmState = muted ? "muted" : "water"
    }
    sendEvent(name: "alarmState", value: alarmState)

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

// ==================== Logging ====================

def logDebug(msg) {
    if (enableDebug) log.debug "[X-Sense Water] ${msg}"
}
