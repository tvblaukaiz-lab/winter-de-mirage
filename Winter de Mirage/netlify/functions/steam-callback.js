
const crypto = require("crypto");

function getCookie(event, name) {
    const cookies = event.headers.cookie ||
        event.headers.Cookie || "";

    const item = cookies
        .split(";")
        .map(value => value.trim())
        .find(value => value.startsWith(name + "="));

    if (!item) return null;

    try {
        return decodeURIComponent(item.slice(name.length + 1));
    } catch {
        return null;
    }
}

function safeEqual(a, b) {
    const first = Buffer.from(a);
    const second = Buffer.from(b);

    return first.length === second.length &&
        crypto.timingSafeEqual(first, second);
}

exports.handler = async (event) => {
    try {
        const secret = process.env.SESSION_SECRET;

        if (!secret || secret.length < 32) {
            return {
                statusCode: 500,
                body: "Steam login is not configured."
            };
        }

        const params = event.queryStringParameters || {};
        const state = params.state || "";
        const cookieValue = getCookie(event, "wmd_state");

        if (!cookieValue) {
            return {
                statusCode: 400,
                body: "Login session expired. Try again."
            };
        }

        const separator = cookieValue.lastIndexOf(".");

        if (separator === -1) {
            return {
                statusCode: 400,
                body: "Invalid login cookie."
            };
        }

        const cookieState = cookieValue.slice(0, separator);
        const cookieSignature = cookieValue.slice(separator + 1);

        const expectedSignature = crypto
            .createHmac("sha256", secret)
            .update(cookieState)
            .digest("hex");

        if (
            !state ||
            state !== cookieState ||
            !safeEqual(cookieSignature, expectedSignature)
        ) {
            return {
                statusCode: 400,
                body: "Invalid login state. Try again."
            };
        }

        const site = "https://stately-gingersnap-93e41a.netlify.app";
        const callback = `${site}/.netlify/functions/steam-callback`;

        if (
            params["openid.return_to"] !==
            `${callback}?state=${state}`
        ) {
            return {
                statusCode: 400,
                body: "Invalid Steam callback."
            };
        }

        const claimedId = params["openid.claimed_id"] || "";
        const identity = params["openid.identity"] || "";

        const match = claimedId.match(
            /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/
        );

        if (!match || identity !== claimedId) {
            return {
                statusCode: 400,
                body: "Invalid Steam account."
            };
        }

        const verification = new URLSearchParams();

        for (const [key, value] of Object.entries(params)) {
            if (key.startsWith("openid.")) {
                verification.set(key, value);
            }
        }

        verification.set("openid.mode", "check_authentication");

        const response = await fetch(
            "https://steamcommunity.com/openid/login",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: verification.toString()
            }
        );

        const result = await response.text();

        if (!response.ok || !/\bis_valid:true\b/.test(result)) {
            return {
                statusCode: 401,
                body: "Steam could not verify the login."
            };
        }

        const payload = Buffer.from(JSON.stringify({
            steamId: match[1],
            issuedAt: Date.now()
        })).toString("base64url");

        const sessionSignature = crypto
            .createHmac("sha256", secret)
            .update(payload)
            .digest("base64url");

        const sessionCookie = `${payload}.${sessionSignature}`;

        return {
            statusCode: 302,
            headers: {
                Location: site
            },
            multiValueHeaders: {
                "Set-Cookie": [
                    `wmd_session=${sessionCookie}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
                    "wmd_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
                ]
            },
            body: ""
        };

    } catch (error) {
        return {
            statusCode: 500,
            body: "Steam login failed. Please try again."
        };
    }
};
