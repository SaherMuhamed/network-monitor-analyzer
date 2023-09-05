from network_analyzer_gui import NetworkAnalyzer

if __name__ == "__main__":
    app = NetworkAnalyzer(interface="Wi-Fi")   # specifiy your network adapter here
    app.run()
