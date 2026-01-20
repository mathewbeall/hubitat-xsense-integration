/**
 *  X-Sense SBS50 Bridge Driver for Hubitat
 *
 *  Copyright 2025
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Description:
 *  Native Hubitat driver for X-Sense smart smoke/CO detectors via the SBS50 bridge.
 *  Uses AWS Cognito SRP authentication to communicate with the X-Sense cloud API.
 *
 *  Supported devices: SC07-MR and other X-Sense Link+ compatible detectors
 */

import groovy.json.JsonBuilder
import groovy.json.JsonSlurper

metadata {
    definition(name: "X-Sense SBS50 Bridge", namespace: "xsense", author: "Community") {
        capability "Refresh"
        capability "Initialize"

        attribute "connectionStatus", "string"
        attribute "lastUpdate", "string"
        attribute "houseCount", "number"
        attribute "stationCount", "number"
        attribute "deviceCount", "number"

        command "login"
        command "discoverDevices"
    }

    preferences {
        input name: "username", type: "text", title: "X-Sense Email", required: true
        input name: "password", type: "password", title: "X-Sense Password", required: true
        input name: "pollInterval", type: "enum", title: "Poll Interval",
              options: ["1": "1 Minute", "5": "5 Minutes", "10": "10 Minutes", "30": "30 Minutes"],
              defaultValue: "5"
        input name: "enableDebug", type: "bool", title: "Enable Debug Logging", defaultValue: true
    }
}

// ==================== Lifecycle Methods ====================

def installed() {
    logInfo "X-Sense driver installed"
    initialize()
}

def updated() {
    logInfo "X-Sense driver updated"
    unschedule()
    initialize()
}

def initialize() {
    logInfo "Initializing X-Sense driver"
    state.clear()
    state.accessToken = null
    state.idToken = null
    state.refreshToken = null
    state.tokenExpiry = 0
    state.clientId = null
    state.clientSecret = null
    state.userPoolId = null
    state.cognitoRegion = "us-east-1"
    state.houses = [:]
    state.stations = [:]
    state.devices = [:]

    sendEvent(name: "connectionStatus", value: "disconnected")

    if (username && password) {
        runIn(5, "login")
    } else {
        logWarn "Please configure X-Sense credentials"
    }
}

def refresh() {
    if (!hasCredentials()) {
        logWarn "Please configure X-Sense credentials before refreshing"
        return
    }
    if (checkTokenValid()) {
        pollDevices()
    } else {
        login()
    }
}

// ==================== Authentication ====================

def login() {
    if (!hasCredentials()) {
        logWarn "Please configure X-Sense credentials before logging in"
        return
    }
    logInfo "Starting X-Sense login"
    sendEvent(name: "connectionStatus", value: "connecting")
    getClientInfo()
}

def getClientInfo() {
    def body = new JsonBuilder([
        bizCode: "101001",
        clientType: "1",
        appVersion: "v1.22.0_20240914.1",
        appCode: "1220",
        mac: "f936c37def1781bd604cf56ce8c5a746"
    ]).toString()

    def params = [
        uri: "https://api.x-sense-iot.com/app",
        contentType: "application/json",
        body: body,
        timeout: 30
    ]

    try {
        httpPost(params) { resp ->
            if (resp.status == 200) {
                def data = resp.data
                if (data.reCode == 200 && data.reData) {
                    def reData = data.reData
                    state.clientId = reData.clientId
                    state.clientSecretRaw = reData.clientSecret
                    state.clientSecret = decodeBase64(reData.clientSecret)
                    state.userPoolId = reData.userPoolId
                    state.cognitoRegion = reData.cgtRegion ?: "us-east-1"
                    logDebug "Got client info - Pool: ${state.userPoolId}"
                    startSrpAuth()
                } else {
                    logError "API error: ${data.reCode} - ${data.reMsg}"
                    sendEvent(name: "connectionStatus", value: "error")
                }
            }
        }
    } catch (e) {
        logError "Failed to get client info: ${e.message}"
        sendEvent(name: "connectionStatus", value: "error")
    }
}

def decodeBase64(String encoded) {
    try {
        return new String(encoded.decodeBase64())
    } catch (e) {
        logError "Failed to decode base64: ${e.message}"
        return encoded
    }
}

def startSrpAuth() {
    logDebug "Starting SRP authentication"

    // Generate ephemeral keypair (a, A)
    def a = generateRandomBigInteger(256)
    def N = getSrpN()
    def g = BigInteger.valueOf(2)
    def A = g.modPow(a, N)

    // Store for later
    state.srpA = a.toString(16)
    state.srpBigA = A.toString(16)

    // Prepare InitiateAuth request
    def authParams = [
        USERNAME: username,
        SRP_A: A.toString(16)
    ]

    if (state.clientSecret) {
        authParams.SECRET_HASH = calculateSecretHash(username)
    }

    def requestBody = new JsonBuilder([
        AuthFlow: "USER_SRP_AUTH",
        ClientId: state.clientId,
        AuthParameters: authParams
    ]).toString()

    def params = [
        uri: "https://cognito-idp.${state.cognitoRegion}.amazonaws.com/",
        requestContentType: "application/json",
        headers: [
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
            "Content-Type": "application/x-amz-json-1.1"
        ],
        body: requestBody,
        timeout: 30
    ]

    try {
        httpPost(params) { resp ->
            def responseText = resp.data.text
            def data = new JsonSlurper().parseText(responseText)
            if (data.ChallengeName == "PASSWORD_VERIFIER") {
                handlePasswordVerifierChallenge(data)
            } else {
                logError "Unexpected challenge: ${data.ChallengeName}"
                sendEvent(name: "connectionStatus", value: "error")
            }
        }
    } catch (groovyx.net.http.HttpResponseException e) {
        logError "SRP auth failed: ${e.message}"
        sendEvent(name: "connectionStatus", value: "error")
    } catch (e) {
        logError "SRP auth failed: ${e.message}"
        sendEvent(name: "connectionStatus", value: "error")
    }
}

def handlePasswordVerifierChallenge(Map challengeData) {
    def challengeParams = challengeData.ChallengeParameters
    def salt = new BigInteger(challengeParams.SALT, 16)
    def B = new BigInteger(challengeParams.SRP_B, 16)
    def secretBlock = challengeParams.SECRET_BLOCK
    def usernameInternal = challengeParams.USER_ID_FOR_SRP

    // Retrieve stored values
    def a = new BigInteger(state.srpA, 16)
    def A = new BigInteger(state.srpBigA, 16)
    def N = getSrpN()
    def g = BigInteger.valueOf(2)

    // Calculate u = H(A || B)
    def uHex = hashBigIntegersToHex(A, B)
    def u = new BigInteger(uHex, 16)

    // Extract pool name from pool ID
    def poolName = state.userPoolId.split("_")[1]

    // Calculate x = H(salt || H(poolName || usernameInternal || ":" || password))
    def userPassStr = poolName + usernameInternal + ":" + password
    def userPassHashHex = bytesToHex(sha256Hash(userPassStr))
    def saltHex = padHexString(salt.toString(16))
    def combinedHex = saltHex + userPassHashHex
    def x = new BigInteger(1, sha256HashBytes(hexToBytes(combinedHex)))

    // Calculate k = H(N || g)
    def k = computeK()

    // Calculate S = (B - k * g^x)^(a + u * x) mod N
    def gx = g.modPow(x, N)
    def kgx = k.multiply(gx)
    def diff = B.subtract(kgx).mod(N)
    def exp = a.add(u.multiply(x))
    def S = diff.modPow(exp, N)

    // Derive key using HKDF
    def sHex = padHexString(S.toString(16))
    def uSaltHex = padHexString(u.toString(16))
    def hkdfKey = computeHkdf(hexToBytes(sHex), hexToBytes(uSaltHex))

    // Generate timestamp and signature
    def timestamp = formatTimestamp()
    def signature = calculateClaimSignature(hkdfKey, poolName, usernameInternal, secretBlock, timestamp)

    // Build challenge response
    def challengeResponses = [
        USERNAME: usernameInternal,
        PASSWORD_CLAIM_SECRET_BLOCK: secretBlock,
        TIMESTAMP: timestamp,
        PASSWORD_CLAIM_SIGNATURE: signature
    ]

    if (state.clientSecret) {
        challengeResponses.SECRET_HASH = calculateSecretHash(usernameInternal)
    }

    def requestBody = new JsonBuilder([
        ChallengeName: "PASSWORD_VERIFIER",
        ClientId: state.clientId,
        ChallengeResponses: challengeResponses
    ]).toString()

    def httpParams = [
        uri: "https://cognito-idp.${state.cognitoRegion}.amazonaws.com/",
        requestContentType: "application/json",
        headers: [
            "X-Amz-Target": "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
            "Content-Type": "application/x-amz-json-1.1"
        ],
        body: requestBody,
        timeout: 30
    ]

    try {
        httpPost(httpParams) { resp ->
            def responseText = resp.data.text
            def data = new JsonSlurper().parseText(responseText)
            if (data.AuthenticationResult) {
                handleAuthSuccess(data.AuthenticationResult)
            } else {
                logError "Auth failed - no result: ${data}"
                sendEvent(name: "connectionStatus", value: "error")
            }
        }
    } catch (groovyx.net.http.HttpResponseException e) {
        logError "Challenge response failed: ${e.message}"
        try {
            def errorText = e.response?.data?.text ?: e.response?.data?.toString()
            logError "Challenge error details: ${errorText}"
        } catch (e2) {
            logError "Could not read error: ${e2.message}"
        }
        sendEvent(name: "connectionStatus", value: "error")
    } catch (e) {
        logError "Challenge response failed: ${e.message}"
        sendEvent(name: "connectionStatus", value: "error")
    }
}

def handleAuthSuccess(Map result) {
    logInfo "Authentication successful!"

    state.accessToken = result.AccessToken
    state.idToken = result.IdToken
    state.refreshToken = result.RefreshToken
    state.tokenExpiry = now() + ((result.ExpiresIn ?: 3600) * 1000)

    sendEvent(name: "connectionStatus", value: "connected")

    // Get AWS tokens and discover devices
    getAwsTokens()
    schedulePolling()

    // Schedule initial data refresh after discovery completes
    runIn(10, "initialRefresh")
}

def initialRefresh() {
    logInfo "Performing initial data refresh after setup"
    pollDevices()
}

def getAwsTokens() {
    // Extra params for MAC calculation (only these, not standard fields)
    def extraParams = [
        userName: username
    ]

    def bodyMap = [
        bizCode: "101003",
        clientType: "1",
        appVersion: "v1.22.0_20240914.1",
        appCode: "1220",
        userName: username,
        mac: calculateMac(extraParams)  // MAC only from extra params
    ]

    def params = [
        uri: "https://api.x-sense-iot.com/app",
        contentType: "application/json",
        headers: [
            "Authorization": state.accessToken
        ],
        body: new JsonBuilder(bodyMap).toString(),
        timeout: 30
    ]

    try {
        httpPost(params) { resp ->
            if (resp.status == 200) {
                def data = resp.data
                if (data.reCode == 200 && data.reData) {
                    state.awsAccessKey = data.reData.accessKeyId
                    state.awsSecretKey = data.reData.secretAccessKey
                    state.awsSessionToken = data.reData.sessionToken
                    discoverDevices()
                } else {
                    logError "Failed to get AWS tokens: ${data.reCode} - ${data.reMsg}"
                }
            }
        }
    } catch (e) {
        logError "Failed to get AWS tokens: ${e.message}"
    }
}

// ==================== Crypto Helper Methods ====================

def getSrpNHex() {
    // SRP-6a 3072-bit prime used by AWS Cognito - uppercase hex string
    return "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
}

def getSrpN() {
    return new BigInteger(getSrpNHex(), 16)
}

def generateRandomBigInteger(int bits) {
    // Generate random BigInteger using Math.random() - works in Hubitat sandbox
    def bytes = new byte[bits / 8]
    for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte)(Math.random() * 256 - 128)
    }
    return new BigInteger(1, bytes)
}

def sha256Hash(String input) {
    def md = java.security.MessageDigest.getInstance("SHA-256")
    return md.digest(input.getBytes("UTF-8"))
}

def sha256HashBytes(byte[] input) {
    def md = java.security.MessageDigest.getInstance("SHA-256")
    return md.digest(input)
}

def hashBigIntegersToHex(BigInteger a, BigInteger b) {
    // Convert to padded hex, concatenate, convert to bytes, then hash
    def aHex = padHexString(a.toString(16))
    def bHex = padHexString(b.toString(16))
    def combinedHex = aHex + bHex
    def combinedBytes = hexToBytes(combinedHex)
    return bytesToHex(sha256HashBytes(combinedBytes))
}

def hashBigIntegers(BigInteger a, BigInteger b) {
    // Convenience method that returns BigInteger
    return new BigInteger(hashBigIntegersToHex(a, b), 16)
}

def computeK() {
    // k = hex_hash("00" + N_HEX + "0" + G_HEX) in pycognito
    // hex_hash converts hex string to BYTES, then hashes
    // "00" prefix for N, "0" + "2" = "02" for g
    def combinedHex = "00" + getSrpNHex() + "02"
    def combinedBytes = hexToBytes(combinedHex)
    def hashHex = bytesToHex(sha256HashBytes(combinedBytes))
    return new BigInteger(hashHex, 16)
}

def hashSaltAndHash(BigInteger salt, byte[] hash) {
    def md = java.security.MessageDigest.getInstance("SHA-256")
    md.update(padHex(salt.toString(16)))
    md.update(hash)
    return new BigInteger(1, md.digest())
}

def padHex(String hex) {
    // Must use else-if to match Python's elif behavior in pad_hex
    def result = hex
    if (result.length() % 2 == 1) {
        result = "0" + result
    } else if (Integer.parseInt(result.substring(0, 2), 16) > 127) {
        result = "00" + result
    }
    return hexToBytes(result)
}

def padHexString(String hex) {
    // Return padded hex as STRING (for concatenation), not bytes
    // Must use else-if to match Python's elif behavior in pad_hex
    def result = hex
    if (result.length() % 2 == 1) {
        result = "0" + result
    } else if (Integer.parseInt(result.substring(0, 2), 16) > 127) {
        result = "00" + result
    }
    return result
}

def hexToBytes(String hex) {
    def len = hex.length()
    def data = new byte[len / 2]
    for (int i = 0; i < len; i += 2) {
        data[(int)(i / 2)] = (byte)((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16))
    }
    return data
}

def bytesToHex(byte[] bytes) {
    def result = new StringBuilder()
    for (byte b : bytes) {
        result.append(String.format("%02x", b))
    }
    return result.toString()
}

def computeHkdf(byte[] ikm, byte[] salt) {
    // HKDF-SHA256 with info = "Caldera Derived Key"
    def mac = javax.crypto.Mac.getInstance("HmacSHA256")

    // Extract
    def saltKey = new javax.crypto.spec.SecretKeySpec(salt.length > 0 ? salt : new byte[32], "HmacSHA256")
    mac.init(saltKey)
    def prk = mac.doFinal(ikm)

    // Expand
    def info = "Caldera Derived Key".getBytes("UTF-8")
    def infoKey = new javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256")
    mac.init(infoKey)
    mac.update(info)
    mac.update((byte) 1)
    def okm = mac.doFinal()

    // Return first 16 bytes
    def result = new byte[16]
    for (int i = 0; i < 16; i++) {
        result[i] = okm[i]
    }
    return result
}

def calculateClaimSignature(byte[] key, String poolName, String userId, String secretBlock, String timestamp) {
    def mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))

    mac.update(poolName.getBytes("UTF-8"))
    mac.update(userId.getBytes("UTF-8"))
    mac.update(secretBlock.decodeBase64())
    mac.update(timestamp.getBytes("UTF-8"))

    return mac.doFinal().encodeBase64().toString()
}

def calculateSecretHash(String user) {
    // Remove first 4 bytes AND last 1 byte from decoded secret
    def fullSecret = state.clientSecret
    def secret = fullSecret
    if (fullSecret?.length() > 5) {
        secret = fullSecret.substring(4, fullSecret.length() - 1)
    }

    def message = user + state.clientId
    def mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"))
    mac.update(message.getBytes("UTF-8"))
    return mac.doFinal().encodeBase64().toString()
}

def formatTimestamp() {
    def now = new Date()
    def sdf = new java.text.SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US)
    sdf.setTimeZone(TimeZone.getTimeZone("UTC"))
    return sdf.format(now)
}

def calculateMac(Map extraParams) {
    // MD5 hash of concatenated extra parameter values + trimmed client secret
    def values = new StringBuilder()

    extraParams.each { key, value ->
        if (value instanceof List) {
            if (value && value[0] instanceof String) {
                value.each { values.append(it) }
            } else {
                values.append(new JsonBuilder(value).toString())
            }
        } else if (value instanceof Map) {
            values.append(new JsonBuilder(value).toString())
        } else {
            values.append(value.toString())
        }
    }

    // Get trimmed secret (first 4 + last 1 removed)
    def fullSecret = state.clientSecret ?: ""
    def trimmedSecret = ""
    if (fullSecret.length() > 5) {
        trimmedSecret = fullSecret.substring(4, fullSecret.length() - 1)
    }

    def macInput = values.toString() + trimmedSecret
    def md = java.security.MessageDigest.getInstance("MD5")
    return bytesToHex(md.digest(macInput.getBytes("UTF-8")))
}

// ==================== Device Discovery ====================

def hasCredentials() {
    return username && password
}

def checkTokenValid() {
    return state.accessToken && state.tokenExpiry > now()
}

def discoverDevices() {
    if (!hasCredentials()) {
        logWarn "Please configure X-Sense credentials before discovering devices"
        return
    }
    logInfo "Discovering X-Sense devices"

    if (!checkTokenValid()) {
        logWarn "Token expired, re-authenticating"
        login()
        return
    }

    getHouses()
}

def getHouses() {
    def extraParams = [utctimestamp: "0"]
    def bodyMap = [
        bizCode: "102007",
        clientType: "1",
        appVersion: "v1.22.0_20240914.1",
        appCode: "1220",
        utctimestamp: "0",
        mac: calculateMac(extraParams)
    ]

    def params = [
        uri: "https://api.x-sense-iot.com/app",
        contentType: "application/json",
        headers: ["Authorization": state.accessToken],
        body: new JsonBuilder(bodyMap).toString(),
        timeout: 30
    ]

    try {
        httpPost(params) { resp ->
            if (resp.status == 200) {
                def data = resp.data
                if (data.reCode == 200 && data.reData) {
                    state.houses = [:]
                    data.reData.each { house ->
                        state.houses[house.houseId] = [
                            name: house.houseName,
                            region: house.houseRegion,
                            mqttRegion: house.mqttRegion,
                            mqttServer: house.mqttServer
                        ]
                        logInfo "Found house: ${house.houseName} (${house.houseId})"
                    }
                    sendEvent(name: "houseCount", value: state.houses.size())
                    logInfo "Found ${state.houses.size()} house(s)"

                    state.houses.each { houseId, house ->
                        getStations(houseId)
                    }
                } else {
                    logError "Failed to get houses: ${data.reCode} - ${data.reMsg}"
                }
            }
        }
    } catch (e) {
        logError "Failed to get houses: ${e.message}"
    }
}

def getStations(String houseId) {
    def extraParams = [houseId: houseId, utctimestamp: "0"]
    def bodyMap = [
        bizCode: "103007",
        clientType: "1",
        appVersion: "v1.22.0_20240914.1",
        appCode: "1220",
        houseId: houseId,
        utctimestamp: "0",
        mac: calculateMac(extraParams)
    ]

    def params = [
        uri: "https://api.x-sense-iot.com/app",
        contentType: "application/json",
        headers: [
            "Authorization": state.accessToken
        ],
        body: new JsonBuilder(bodyMap).toString(),
        timeout: 30
    ]

    try {
        httpPost(params) { resp ->
            if (resp.status == 200) {
                def data = resp.data
                if (data.reCode == 200 && data.reData) {
                    // Stations are in reData.stations array
                    def stationsList = data.reData.stations ?: []
                    stationsList.each { station ->
                        def stationId = station.stationSn
                        state.stations[stationId] = [
                            houseId: houseId,
                            name: station.stationName,
                            type: station.category,
                            online: station.onLine == 1,
                            stationId: station.stationId
                        ]
                        logInfo "Found station: ${station.stationName} (${stationId}) type: ${station.category}"

                        // Devices are in station.devices array
                        station.devices?.each { device ->
                            processDevice(stationId, device)
                        }
                    }
                    sendEvent(name: "stationCount", value: state.stations.size())
                    logInfo "Found ${state.stations.size()} station(s) total"
                } else {
                    logError "Failed to get stations: ${data.reCode} - ${data.reMsg}"
                }
            }
        }
    } catch (e) {
        logError "Failed to get stations: ${e.message}"
    }
}

def processDevice(String stationId, Map device) {
    def deviceSn = device.deviceSn ?: device.deviceId
    def deviceType = device.deviceType
    def deviceName = device.deviceName ?: "X-Sense Device"

    logInfo "Processing device: ${deviceName} (${deviceSn}) type: ${deviceType}"

    state.devices[deviceSn] = [
        stationId: stationId,
        deviceId: device.deviceId,
        name: deviceName,
        type: deviceType,
        roomId: device.roomId,
        lastUpdate: now()
    ]

    createChildDevice(deviceSn, deviceName, deviceType)
    sendEvent(name: "deviceCount", value: state.devices.size())
}

def createChildDevice(String deviceId, String deviceName, String deviceType) {
    def dni = "${device.deviceNetworkId}-${deviceId}"
    def childDevice = getChildDevice(dni)

    if (!childDevice) {
        logInfo "Creating child device: ${deviceName}"

        try {
            childDevice = addChildDevice("xsense", "X-Sense Smoke/CO Detector", dni, [
                name: deviceName,
                label: deviceName,
                isComponent: false
            ])
        } catch (e) {
            logWarn "Custom driver not found, using generic: ${e.message}"
            try {
                childDevice = addChildDevice("hubitat", "Virtual Smoke Detector", dni, [
                    name: deviceName,
                    label: deviceName,
                    isComponent: false
                ])
            } catch (e2) {
                logError "Failed to create child device: ${e2.message}"
            }
        }
    }

    if (childDevice) {
        def deviceData = state.devices[deviceId]
        if (deviceData) {
            childDevice.sendEvent(name: "battery", value: deviceData.battery ?: 100, unit: "%")

            def smokeStatus = (deviceData.status?.smoke == 1) ? "detected" : "clear"
            def coStatus = (deviceData.status?.co == 1) ? "detected" : "clear"

            childDevice.sendEvent(name: "smoke", value: smokeStatus)
            childDevice.sendEvent(name: "carbonMonoxide", value: coStatus)
        }
    }
}

// ==================== Polling ====================

def schedulePolling() {
    def interval = (pollInterval ?: "5").toInteger()
    switch(interval) {
        case 1:
            runEvery1Minute("pollDevices")
            break
        case 5:
            runEvery5Minutes("pollDevices")
            break
        case 10:
            runEvery10Minutes("pollDevices")
            break
        case 30:
            runEvery30Minutes("pollDevices")
            break
        default:
            runEvery5Minutes("pollDevices")
    }
}

def pollDevices() {
    if (!checkTokenValid()) {
        login()
        return
    }

    // Poll each station for device status via shadow API
    def deviceCount = 0
    state.stations.each { stationSn, station ->
        def house = state.houses[station.houseId]
        if (house) {
            deviceCount += getStationShadow(stationSn, station, house)
        }
    }

    logInfo "Polled ${deviceCount} device(s)"
    sendEvent(name: "lastUpdate", value: new Date().format("yyyy-MM-dd HH:mm:ss"))
}

// ==================== AWS IoT Shadow API ====================

def getStationShadow(String stationSn, Map station, Map house) {
    def mqttRegion = house.mqttRegion ?: "us-east-1"
    def host = "${mqttRegion}.x-sense-iot.com"

    // Build thing name based on station type
    def typeName = station.type ?: ""
    if (typeName == "SBS10") typeName = ""
    if (typeName in ["XC04-WX", "SC07-WX"]) typeName += "-"

    // Try different shadow pages
    def pages = ["2nd_mainpage", "mainpage"]
    def deviceCount = 0

    for (page in pages) {
        if (deviceCount > 0) break

        def uri = "/things/${typeName}${stationSn}/shadow?name=${page}"
        def url = "https://${host}${uri}"

        def headers = [
            "Content-Type": "application/x-amz-json-1.0",
            "User-Agent": "aws-sdk-iOS/2.26.5 iOS/17.3 en_US",
            "X-Amz-Security-Token": state.awsSessionToken
        ]

        // Sign the request with AWS Signature V4
        def signedHeaders = signAwsRequest("GET", url, mqttRegion, headers, null)
        headers.putAll(signedHeaders)

        def params = [
            uri: url,
            headers: headers,
            timeout: 30
        ]

        try {
            httpGet(params) { resp ->
                if (resp.status == 200) {
                    def data = resp.data
                    if (data?.state?.reported?.devs) {
                        deviceCount = data.state.reported.devs.size()
                        parseDeviceStatus(stationSn, data.state.reported)
                    }
                }
            }
        } catch (groovyx.net.http.HttpResponseException e) {
            if (e.statusCode == 404) {
                continue  // Try next shadow page
            }
            logError "Shadow API error for ${stationSn}: ${e.statusCode}"
        } catch (e) {
            logError "Failed to get shadow for ${stationSn}: ${e.message}"
        }
    }
    return deviceCount
}

def parseDeviceStatus(String stationSn, Map reported) {
    reported.devs?.each { deviceSn, deviceData ->
        updateChildDevice(deviceSn, deviceData)
    }
}

def updateChildDevice(String deviceSn, Map deviceData) {
    def dni = "${device.deviceNetworkId}-${deviceSn}"
    def childDevice = getChildDevice(dni)
    if (!childDevice) return

    // Update battery level - batInfo is 0-3 (bars), convert to percentage
    if (deviceData.batInfo != null) {
        def batLevel = deviceData.batInfo as Integer
        def batteryMap = [0: 0, 1: 33, 2: 66, 3: 100]
        childDevice.sendEvent(name: "battery", value: batteryMap[batLevel] ?: 0, unit: "%")
    }

    // Update smoke/CO status from alarmStatus in status object
    // alarmStatus: 0 = clear, 1 = smoke alarm, 2 = CO alarm, 3 = both?
    def alarmStatus = (deviceData.status?.alarmStatus ?: 0) as Integer
    def coLevel = (deviceData.coLevel ?: 0) as Integer

    // Smoke status
    def smokeStatus = "clear"
    if (alarmStatus == 1 || alarmStatus == 3) {
        smokeStatus = "detected"
    }
    childDevice.sendEvent(name: "smoke", value: smokeStatus)

    // CO status - check both alarmStatus and coLevel
    def coStatus = "clear"
    if (alarmStatus == 2 || alarmStatus == 3 || coLevel > 0) {
        coStatus = "detected"
    }
    childDevice.sendEvent(name: "carbonMonoxide", value: coStatus)

    // Update CO PPM if available
    if (deviceData.coPpm != null) {
        childDevice.sendEvent(name: "carbonMonoxideLevel", value: deviceData.coPpm, unit: "ppm")
    }

    // Update temperature if available
    if (deviceData.temperature != null) {
        childDevice.sendEvent(name: "temperature", value: deviceData.temperature, unit: "°F")
    }

    // Update humidity if available
    if (deviceData.humidity != null) {
        childDevice.sendEvent(name: "humidity", value: deviceData.humidity, unit: "%")
    }

    // Update signal strength - rfLevel is 0-3 (bars)
    if (deviceData.rfLevel != null) {
        def rfLevel = deviceData.rfLevel as Integer
        def rssiMap = [0: -90, 1: -70, 2: -50, 3: -30]
        def rssi = rssiMap[rfLevel] ?: -90
        childDevice.sendEvent(name: "rssi", value: rssi, unit: "dBm")

        def signalStr = "unknown"
        if (rssi >= -50) signalStr = "excellent"
        else if (rssi >= -60) signalStr = "good"
        else if (rssi >= -70) signalStr = "fair"
        else signalStr = "poor"
        childDevice.sendEvent(name: "signalStrength", value: signalStr)
    }

    // Update online status
    if (deviceData.online != null) {
        def onlineVal = deviceData.online as Integer
        def status = onlineVal == 1 ? "online" : "offline"
        childDevice.sendEvent(name: "healthStatus", value: status)
        childDevice.sendEvent(name: "deviceStatus", value: status)
    }

    // Update lastChecked timestamp
    childDevice.sendEvent(name: "lastChecked", value: new Date().format("yyyy-MM-dd HH:mm:ss"))
}

// ==================== AWS Signature V4 ====================

def signAwsRequest(String method, String url, String region, Map headers, String content) {
    def service = "iotdata"

    // Parse URL
    def uri = new java.net.URI(url)
    def host = uri.host
    def path = uri.path
    def query = uri.query ?: ""

    // Get current time
    def now = new Date()
    def sdf = new java.text.SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'")
    sdf.setTimeZone(TimeZone.getTimeZone("UTC"))
    def amzDate = sdf.format(now)
    def dateStamp = amzDate.substring(0, 8)

    // Calculate content hash
    def contentHash = bytesToHex(sha256HashBytes(content?.getBytes("UTF-8") ?: new byte[0]))

    // Build result headers
    def result = [
        "host": host,
        "X-Amz-Date": amzDate
    ]

    // Combine and sort headers for signing
    def allHeaders = [:]
    allHeaders.putAll(headers)
    allHeaders.putAll(result)

    def sortedHeaders = allHeaders.collectEntries { k, v -> [(k.toLowerCase()): v] }.sort()
    def signedHeadersList = sortedHeaders.keySet().join(";")

    // Build canonical request
    def canonicalHeaders = sortedHeaders.collect { k, v -> "${k}:${v}" }.join("\n")
    def canonicalQueryString = query.split("&").sort().join("&")

    def canonicalRequest = [
        method,
        path,
        canonicalQueryString,
        canonicalHeaders,
        "",
        signedHeadersList,
        contentHash
    ].join("\n")

    // Build string to sign
    def scope = "${dateStamp}/${region}/${service}/aws4_request"
    def stringToSign = [
        "AWS4-HMAC-SHA256",
        amzDate,
        scope,
        bytesToHex(sha256HashBytes(canonicalRequest.getBytes("UTF-8")))
    ].join("\n")

    // Calculate signature
    def signingKey = getAwsSigningKey(dateStamp, region, service)
    def signature = bytesToHex(hmacSha256(signingKey, stringToSign))

    // Build Authorization header
    def credential = "${state.awsAccessKey}/${scope}"
    result["Authorization"] = "AWS4-HMAC-SHA256 Credential=${credential}, SignedHeaders=${signedHeadersList}, Signature=${signature}"

    return result
}

def getAwsSigningKey(String dateStamp, String region, String service) {
    def kDate = hmacSha256(("AWS4" + state.awsSecretKey).getBytes("UTF-8"), dateStamp)
    def kRegion = hmacSha256(kDate, region)
    def kService = hmacSha256(kRegion, service)
    def kSigning = hmacSha256(kService, "aws4_request")
    return kSigning
}

def hmacSha256(byte[] key, String data) {
    def mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data.getBytes("UTF-8"))
}

// ==================== Logging ====================

def logDebug(msg) {
    if (enableDebug) log.debug "[X-Sense] ${msg}"
}

def logInfo(msg) {
    log.info "[X-Sense] ${msg}"
}

def logWarn(msg) {
    log.warn "[X-Sense] ${msg}"
}

def logError(msg) {
    log.error "[X-Sense] ${msg}"
}
