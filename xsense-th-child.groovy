/**
 *  X-Sense Temperature/Humidity Sensor Child Driver for Hubitat
 *
 *  Copyright 2025
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Description:
 *  Child driver for X-Sense temperature and humidity sensors (STH0B, STH51 and compatible models).
 *  Works in conjunction with the X-Sense Integration parent app.
 *
 *  The parent app creates this child for any device whose X-Sense type begins with "STH".
 *  The parent converts temperatures to the hub's temperature scale before sending them here.
 */

metadata {
    definition(name: "X-Sense Temperature/Humidity Sensor", namespace: "xsense", author: "Community") {
        capability "Temperature Measurement"
        capability "Relative Humidity Measurement"
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
        attribute "alarmState", "string"      // idle / alarm (reading outside configured range)
        attribute "temperatureRangeLow", "number"
        attribute "temperatureRangeHigh", "number"
        attribute "humidityRangeLow", "number"
        attribute "humidityRangeHigh", "number"
    }

    preferences {
        input name: "enableDebug", type: "bool", title: "Enable Debug Logging", defaultValue: false
    }
}

// ==================== Lifecycle Methods ====================

def installed() {
    logDebug "X-Sense Temperature/Humidity Sensor child device installed"
    initialize()
}

def updated() {
    logDebug "X-Sense Temperature/Humidity Sensor child device updated"
}

def initialize() {
    sendEvent(name: "alarmState", value: "idle")
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
 *   temperature:   number, already in the hub's scale
 *   humidity:      number, percent
 *   alarm:         true/1 = reading outside the configured range
 *   tempRange:     [low, high] in the hub's scale
 *   humidityRange: [low, high] percent
 *   battery, rssi, online: as for the other X-Sense child drivers
 */
def updateStatus(Map status) {
    logDebug "Updating status: ${status}"

    def scale = location.temperatureScale ?: "F"

    if (status.containsKey("temperature")) {
        sendEvent(name: "temperature", value: status.temperature, unit: "°${scale}")
    }

    if (status.containsKey("humidity")) {
        sendEvent(name: "humidity", value: status.humidity, unit: "%")
    }

    if (status.containsKey("alarm")) {
        def alarm = (status.alarm == 1 || status.alarm == true || status.alarm == "1")
        sendEvent(name: "alarmState", value: alarm ? "alarm" : "idle")
    }

    if (status.tempRange instanceof List && status.tempRange.size() == 2) {
        sendEvent(name: "temperatureRangeLow", value: status.tempRange[0], unit: "°${scale}")
        sendEvent(name: "temperatureRangeHigh", value: status.tempRange[1], unit: "°${scale}")
    }

    if (status.humidityRange instanceof List && status.humidityRange.size() == 2) {
        sendEvent(name: "humidityRangeLow", value: status.humidityRange[0], unit: "%")
        sendEvent(name: "humidityRangeHigh", value: status.humidityRange[1], unit: "%")
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
    if (enableDebug) log.debug "[X-Sense T/H] ${msg}"
}
