package com.packetanalyzer.types;

public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    public static String toString(AppType type) {
        if (type == null) return "Unknown";
        switch (type) {
            case UNKNOWN:    return "Unknown";
            case HTTP:       return "HTTP";
            case HTTPS:      return "HTTPS";
            case DNS:        return "DNS";
            case TLS:        return "TLS";
            case QUIC:       return "QUIC";
            case GOOGLE:     return "Google";
            case FACEBOOK:   return "Facebook";
            case YOUTUBE:    return "YouTube";
            case TWITTER:    return "Twitter/X";
            case INSTAGRAM:  return "Instagram";
            case NETFLIX:    return "Netflix";
            case AMAZON:     return "Amazon";
            case MICROSOFT:  return "Microsoft";
            case APPLE:      return "Apple";
            case WHATSAPP:   return "WhatsApp";
            case TELEGRAM:   return "Telegram";
            case TIKTOK:     return "TikTok";
            case SPOTIFY:    return "Spotify";
            case ZOOM:       return "Zoom";
            case DISCORD:    return "Discord";
            case GITHUB:     return "GitHub";
            case CLOUDFLARE: return "Cloudflare";
            default:         return "Unknown";
        }
    }

    public static AppType fromString(String name) {
        for (AppType t : values()) {
            if (toString(t).equalsIgnoreCase(name) || t.name().equalsIgnoreCase(name)) {
                return t;
            }
        }
        return UNKNOWN;
    }

    /** Map an SNI/domain string to an AppType */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("ytimg") || s.contains("youtu.be") || s.contains("yt3.ggpht"))
            return YOUTUBE;
        if (s.contains("google") || s.contains("gstatic") || s.contains("googleapis") || s.contains("ggpht") || s.contains("gvt1"))
            return GOOGLE;
        if (s.contains("instagram") || s.contains("cdninstagram"))
            return INSTAGRAM;
        if (s.contains("whatsapp") || s.contains("wa.me"))
            return WHATSAPP;
        if (s.contains("facebook") || s.contains("fbcdn") || s.contains("fb.com") || s.contains("fbsbx") || s.contains("meta.com"))
            return FACEBOOK;
        if (s.contains("twitter") || s.contains("twimg") || s.contains("x.com") || s.contains("t.co"))
            return TWITTER;
        if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg"))
            return NETFLIX;
        if (s.contains("amazon") || s.contains("amazonaws") || s.contains("cloudfront") || s.contains("aws"))
            return AMAZON;
        if (s.contains("microsoft") || s.contains("msn.com") || s.contains("office") || s.contains("azure")
                || s.contains("live.com") || s.contains("outlook") || s.contains("bing"))
            return MICROSOFT;
        if (s.contains("apple") || s.contains("icloud") || s.contains("mzstatic") || s.contains("itunes"))
            return APPLE;
        if (s.contains("telegram") || s.contains("t.me"))
            return TELEGRAM;
        if (s.contains("tiktok") || s.contains("tiktokcdn") || s.contains("musical.ly") || s.contains("bytedance"))
            return TIKTOK;
        if (s.contains("spotify") || s.contains("scdn.co"))
            return SPOTIFY;
        if (s.contains("zoom"))
            return ZOOM;
        if (s.contains("discord") || s.contains("discordapp"))
            return DISCORD;
        if (s.contains("github") || s.contains("githubusercontent"))
            return GITHUB;
        if (s.contains("cloudflare") || s.contains("cf-"))
            return CLOUDFLARE;

        return HTTPS;
    }
}
