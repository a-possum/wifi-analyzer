from dataclasses import dataclass

from .radio import channel_frequency


def overlap(first, second):
    return max(0, min(first[1], second[1]) - max(first[0], second[0]))


def possible_channels(band):
    if band == "2,4":
        return tuple(range(1, 15))
    if band == "5":
        return tuple(range(36, 65, 4)) + tuple(range(100, 145, 4)) + tuple(range(149, 178, 4))
    return tuple(range(1, 234, 4))


def blocks(band, width):
    channels = possible_channels(band)
    if width == 20:
        return [(channel,) for channel in channels]
    if band == "2,4":
        return [(channel, channel + 4) for channel in range(1, 10)] if width == 40 else []
    size = width // 20
    groups = (channels,) if band == "6" else (channels[:8], channels[8:20], channels[20:])
    return [group[index:index + size] for group in groups
            for index in range(0, len(group) - size + 1, size)]


@dataclass(frozen=True)
class Recommendation:
    channels: tuple[int, ...]
    width: int
    score: float
    overlapping: int
    unknown_width: int
    confidence: str


def recommend(networks, band, allowed, own=None):
    neighbors = [net for net in networks if net.band == band and net.bssid != own]
    result = []
    for width in (20, 40, 80):
        for group in blocks(band, width):
            if not set(group) <= allowed:
                continue
            start = channel_frequency(band, group[0]) - 10
            end = channel_frequency(band, group[-1]) + 10
            score = 0.0
            crossing = uncertain = 0
            for network in neighbors:
                power = 10 ** ((network.rssi + 70) / 10)
                spans = network.spans()
                if spans:
                    fraction = sum(overlap((start, end), span) for span in spans) / width
                    crossing += fraction > 0
                    score += power * fraction
                elif network.frequency is not None:
                    uncertain += 1
                    if start <= network.frequency <= end:
                        score += power
            confidence = "Низкая" if uncertain or not neighbors else "Умеренная"
            result.append(Recommendation(group, width, score, crossing, uncertain, confidence))
    return sorted(result, key=lambda option: (option.width, option.score, option.channels))
