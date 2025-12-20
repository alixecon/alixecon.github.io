from flask import Flask, render_template, request, jsonify
import yfinance as yf
import talib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json

app = Flask(__name__)

# Trading Agent Class (from initial response, expanded)
class DayTradingAgent:
    def __init__(self, symbol='AAPL'):
        self.symbol = symbol
        self.data = None
        self.signals = []

    def fetch_data(self):
        # Fetch 1-day intraday data (1-minute intervals)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=1)
        self.data = yf.download(self.symbol, start=start_date, end=end_date, interval='1m')
        if self.data.empty:
            raise ValueError("No data fetched. Check symbol or internet.")

    def analyze(self):
        if self.data is None:
            self.fetch_data()
        close = self.data['Close'].values
        rsi = talib.RSI(close, timeperiod=14)
        sma_short = talib.SMA(close, timeperiod=5)
        sma_long = talib.SMA(close, timeperiod=10)
        
        self.signals = []
        for i in range(1, len(close)):
            if rsi[i] < 30 and close[i] > close[i-1] and sma_short[i] > sma_long[i]:
                self.signals.append({
                    'timestamp': self.data.index[i].strftime('%H:%M'),
                    'action': 'BUY',
                    'reason': f'RSI {rsi[i]:.2f} < 30, rising price, MA crossover',
                    'price': close[i]
                })
            elif rsi[i] > 70 and close[i] < close[i-1]:
                self.signals.append({
                    'timestamp': self.data.index[i].strftime('%H:%M'),
                    'action': 'SELL',
                    'reason': f'RSI {rsi[i]:.2f} > 70, falling price',
                    'price': close[i]
                })

    def get_signals(self):
        self.analyze()
        return self.signals[-10:]  # Last 10 signals

    def simulate_trade(self, action, qty=10):
        # Mock simulation: No real execution
        current_price = self.data['Close'].iloc[-1] if not self.data.empty else 100
        if action == 'BUY':
            return f"Simulated BUY: {qty} shares of {self.symbol} at ~${current_price:.2f}"
        elif action == 'SELL':
            return f"Simulated SELL: {qty} shares of {self.symbol} at ~${current_price:.2f}"
        return "Invalid action"

# Global agent instance
agent = DayTradingAgent()

@app.route('/')
def dashboard():
    signals = agent.get_signals()
    # Simple chart data (last 50 prices)
    chart_data = agent.data['Close'].tail(50).tolist() if agent.data is not None else []
    return render_template('dashboard.html', signals=signals, chart_data=json.dumps(chart_data))

@app.route('/signals')
def signals_page():
    signals = agent.get_signals()
    return render_template('signals.html', signals=signals)

@app.route('/simulate', methods=['POST'])
def simulate_trade():
    action = request.form.get('action')
    qty = int(request.form.get('qty', 10))
    result = agent.simulate_trade(action, qty)
    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)
