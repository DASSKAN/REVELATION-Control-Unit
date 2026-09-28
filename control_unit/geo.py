"""
Pixel -> ground coordinate projection, plus distance/bearing helpers.

Assumes flat ground at the drone's take-off altitude (alt_agl is height above
that ground). Good enough to put an RPF officer within a few metres on a
platform or in a yard; error grows with range and with heading/pitch error.
"""
import math

EARTH_R = 6371000.0
M_PER_DEG_LAT = 111320.0


def pixel_to_ground(u, v, img_w, img_h, lat, lon, alt_agl, heading_deg, pitch_deg, hfov_deg,
                    max_range_m=400.0):
    """
    u, v          pixel (use the bottom-centre of a bounding box = where it touches the ground)
    heading_deg   drone/camera yaw, clockwise from true north
    pitch_deg     camera pitch; 0 = horizon, -90 = straight down
    Returns (lat, lon, ground_range_m) or None if the ray does not hit the ground in range.
    """
    if lat is None or lon is None or alt_agl is None or alt_agl <= 0.5:
        return None
    f = (img_w / 2.0) / math.tan(math.radians(hfov_deg) / 2.0)
    u, v = float(u), float(v)
    x = (u - img_w / 2.0) / f          # right
    y = (v - img_h / 2.0) / f          # down
    t = math.radians(-pitch_deg)       # tilt below horizon, 90 = nadir
    fwd = math.cos(t) - y * math.sin(t)
    right = x
    down = math.sin(t) + y * math.cos(t)
    if down <= 1e-6:
        return None                    # at or above the horizon
    s = alt_agl / down
    f_m, r_m = s * fwd, s * right
    rng = math.hypot(f_m, r_m)
    if rng > max_range_m:
        return None
    h = math.radians(heading_deg or 0.0)
    north = f_m * math.cos(h) - r_m * math.sin(h)
    east = f_m * math.sin(h) + r_m * math.cos(h)
    la, lo = offset(lat, lon, north, east)
    return (float(la), float(lo), float(rng))


def offset(lat, lon, north_m, east_m):
    dlat = north_m / M_PER_DEG_LAT
    dlon = east_m / (M_PER_DEG_LAT * math.cos(math.radians(lat)))
    return (lat + dlat, lon + dlon)


def distance_m(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_R * math.asin(math.sqrt(a))


def bearing_deg(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360) % 360


if __name__ == "__main__":
    # sanity checks
    lat, lon = 13.0827, 80.2757
    # straight down, centre pixel -> directly under the drone
    print(pixel_to_ground(640, 360, 1280, 720, lat, lon, 30, 0, -90, 90))
    # 45 deg down, centre pixel, heading north, 30 m up -> ~30 m north
    r = pixel_to_ground(640, 360, 1280, 720, lat, lon, 30, 0, -45, 90)
    print(r, distance_m(lat, lon, r[0], r[1]), bearing_deg(lat, lon, r[0], r[1]))
    # same but heading east
    r = pixel_to_ground(640, 360, 1280, 720, lat, lon, 30, 90, -45, 90)
    print(r, distance_m(lat, lon, r[0], r[1]), bearing_deg(lat, lon, r[0], r[1]))
