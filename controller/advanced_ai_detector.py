from datetime import datetime


class AdvancedAIDetector:
    """
    Advanced AI-like detector based on traffic rate and behavior indicators.

    This detector does not depend only on total packet count.
    It compares current counter values with previous counter values
    and calculates packet rate, byte rate, average packet size, and risk score.
    """

    def __init__(self):
        self.previous_packets = 0
        self.previous_bytes = 0
        self.previous_time = None

    def analyze(self, current_packets, current_bytes):
        current_time = datetime.now()

        if self.previous_time is None:
            self.previous_packets = current_packets
            self.previous_bytes = current_bytes
            self.previous_time = current_time

            return {
                "delta_packets": 0,
                "delta_bytes": 0,
                "time_window": 0,
                "packet_rate": 0,
                "byte_rate": 0,
                "avg_packet_size": 0,
                "risk_score": 0,
                "classification": "normal",
                "recommended_action": "allow",
                "reason": "Initial baseline collected"
            }

        time_window = (current_time - self.previous_time).total_seconds()

        if time_window <= 0:
            time_window = 1

        delta_packets = current_packets - self.previous_packets
        delta_bytes = current_bytes - self.previous_bytes

        if delta_packets < 0:
            delta_packets = 0

        if delta_bytes < 0:
            delta_bytes = 0

        packet_rate = delta_packets / time_window
        byte_rate = delta_bytes / time_window

        if delta_packets > 0:
            avg_packet_size = delta_bytes / delta_packets
        else:
            avg_packet_size = 0

        risk_score = self.calculate_risk_score(
            delta_packets=delta_packets,
            packet_rate=packet_rate,
            byte_rate=byte_rate,
            avg_packet_size=avg_packet_size
        )

        classification, recommended_action, reason = self.classify(risk_score, packet_rate, delta_packets)

        self.previous_packets = current_packets
        self.previous_bytes = current_bytes
        self.previous_time = current_time

        return {
            "delta_packets": round(delta_packets, 2),
            "delta_bytes": round(delta_bytes, 2),
            "time_window": round(time_window, 2),
            "packet_rate": round(packet_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "avg_packet_size": round(avg_packet_size, 2),
            "risk_score": risk_score,
            "classification": classification,
            "recommended_action": recommended_action,
            "reason": reason
        }

    def calculate_risk_score(self, delta_packets, packet_rate, byte_rate, avg_packet_size):
        score = 0

        # Packet burst detection
        if delta_packets >= 5:
            score += 10

        if delta_packets >= 10:
            score += 20

        if delta_packets >= 15:
            score += 25

        if delta_packets >= 30:
            score += 35

        if delta_packets >= 60:
            score += 45

        # Packet rate detection
        if packet_rate >= 2:
            score += 10

        if packet_rate >= 4:
            score += 25

        if packet_rate >= 8:
            score += 35

        if packet_rate >= 15:
            score += 45

        # Byte rate detection
        if byte_rate >= 200:
            score += 5

        if byte_rate >= 400:
            score += 10

        if byte_rate >= 1000:
            score += 20

        if byte_rate >= 3000:
            score += 30

        # Small repeated packets may indicate ping flood or probing
        if 40 <= avg_packet_size <= 150 and packet_rate >= 3:
            score += 20

        # Continuous probing pattern
        if delta_packets >= 10 and 40 <= avg_packet_size <= 150:
            score += 15

        if score > 100:
            score = 100
        return score

    def classify(self, risk_score, packet_rate, delta_packets):
        if risk_score < 30:
            return (
                "normal",
                "allow",
                "Low traffic rate and no abnormal burst detected"
            )

        if risk_score < 60:
            return (
                "suspicious",
                "monitor",
                "Moderate traffic increase detected"
            )

        if risk_score < 80:
            return (
                "malicious",
                "redirect",
                "High traffic rate detected, redirecting attacker to honeypot"
            )

        return (
            "critical",
            "redirect",
            "Critical traffic burst detected, attacker must stay in honeypot"
        )
