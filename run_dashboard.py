import sys

sys.path.insert(0, r"C:\Sniffer packet")

from netsentry.api.routes import create_app
from netsentry.detection.engine import DetectionEngine
from netsentry.utils.stats import StatsAggregator


app = create_app(DetectionEngine(), StatsAggregator())
app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)
