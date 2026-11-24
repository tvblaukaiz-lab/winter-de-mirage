
const crypto = require("crypto");

function safeEqual(a, b) {
    const first = Buffer.from(a);
    const second = Buffer.from(b);

    return first.length === second.length &&
        crypto.timingSafeEqual(first, second);
}

function response(data, statusCode = 200) {
    return {
        statusCode,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
        },
        body: JSON.stringify(data)
    };
}

exports.handler = async (event) => {
    try {
        const secret = process.env.SESSION_SECRET;

        if (!secret || secret.length < 32) {
            return response({
                loggedIn: false,
                error: "SESSION_SECRET is missing or too short."
            }, 500);
        }

        const cookies = event.headers.cookie ||
            event.headers.Cookie || "";

        const sessionCookie = cookies
            .split(";")
            .map(item => item.trim())
            .find(item => item.startsWith("wmd_session="));

        if (!sessionCookie) {
            return response({ loggedIn: false });
        }

        const value = decodeURIComponent(
            sessionCookie.slice("wmd_session=".length)
        );

        const separator = value.lastIndexOf(".");

        if (separator === -1) {
            return response({ loggedIn: false });
        }

        const payload = value.slice(0, separator);
        const signature = value.slice(separator + 1);

        const expectedSignature = crypto
            .createHmac("sha256", secret)
            .update(payload)
            .digest("base64url");

        if (!signature ||
            !safeEqual(signature, expectedSignature)) {
            return response({ loggedIn: false });
        }

        const session = JSON.parse(
            Buffer.from(payload, "base64url").toString("utf8")
        );

        const maxAge = 7 * 24 * 60 * 60 * 1000;

        if (
            !session.steamId ||
            !/^\d{17}$/.test(session.steamId) ||
            !session.issuedAt ||
            Date.now() - session.issuedAt > maxAge ||
            session.issuedAt > Date.now() + 60000
        ) {
            return response({ loggedIn: false });
        }

        return response({
            loggedIn: true,
            steamId: session.steamId
        });

    } catch (error) {
        return response({
            loggedIn: false,
            error: "Could not check Steam session."
        }, 500);
    }
};
