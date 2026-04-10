"""
NIDS Web Dashboard
Lightweight Flask dashboard for monitoring alerts and traffic statistics.
"""

import logging
import os
import threading
from flask import Flask, render_template, jsonify

logger = logging.getLogger(__name__)


def create_app(alert_manager, traffic_analyzer, database=None, health_monitor=None):
    """Create and configure the Flask dashboard app"""
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    static_dir = os.path.join(os.path.dirname(__file__), 'static')

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/api/alerts/recent')
    def api_recent_alerts():
        if database:
            alerts = database.recent_alerts(50)
            return jsonify(alerts)
        else:
            alerts_list = list(alert_manager.alerts)[-50:]
            safe = []
            for a in alerts_list:
                entry = {k: str(v) if k == 'timestamp' else v
                         for k, v in a.items()}
                safe.append(entry)
            return jsonify(safe)

    @app.route('/api/alerts/summary')
    def api_alert_summary():
        if database:
            return jsonify({
                'total': database.total_count(),
                'by_severity': database.count_by_severity(),
                'by_type': database.count_by_type(),
            })
        return jsonify(alert_manager.get_alert_summary())

    @app.route('/api/stats/traffic')
    def api_traffic_stats():
        summary = traffic_analyzer.get_summary()
        # Convert non-serializable items
        summary['top_talkers'] = [{'ip': ip, 'count': c} for ip, c in summary.get('top_talkers', [])]
        summary['top_ports'] = [{'port': p, 'count': c} for p, c in summary.get('top_ports', [])]
        return jsonify(summary)

    @app.route('/api/health')
    def api_health():
        if health_monitor:
            return jsonify(health_monitor.get_metrics())
        return jsonify({'status': 'ok'})

    return app


def start_dashboard(alert_manager, traffic_analyzer, database=None,
                    health_monitor=None, host='0.0.0.0', port=5000):
    """Start the dashboard in a background thread"""
    app = create_app(alert_manager, traffic_analyzer, database, health_monitor)

    def run():
        app.run(host=host, port=port, debug=False, use_reloader=False)

    thread = threading.Thread(target=run, name='nids-dashboard', daemon=True)
    thread.start()
    logger.info("Dashboard started at http://%s:%d", host, port)
    return thread
