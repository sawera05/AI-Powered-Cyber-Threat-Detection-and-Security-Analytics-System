class VisualizationManager:

    # 1. Bar Chart
    def attack_graph(self, df):

        attack_counts = df["Event_Type"].value_counts()

        data = [
            {"attackType": k, "frequency": int(v)}
            for k, v in attack_counts.items()
        ]

        return {
            "chartType": "bar",
            "meta": {
                "title": "Cyber Attack Types",
                "description": "Frequency distribution of attack events"
            },
            "xKey": "attackType",
            "series": [{
                "dataKey": "frequency",
                "label": "Frequency",
                "valueFormat": "integer"
            }],
            "data": data
        }

    # 2. Pie Chart
    def malware_graph(self, df):

        malware = df[df["Malware"] != "None"]["Malware"].value_counts()

        data = [
            {"malware": k, "count": int(v)}
            for k, v in malware.items()
        ]

        return {
            "chartType": "pie",
            "meta": {
                "title": "Malware Distribution",
                "description": "Types of malware detected"
            },
            "nameKey": "malware",
            "valueKey": "count",
            "series": [{
                "dataKey": "count",
                "label": "Count",
                "valueFormat": "integer"
            }],
            "data": data
        }

    # 3. Horizontal Bar
    def ip_graph(self, df):

        ips = df["IP_Address"].value_counts()

        data = [
            {"ip": k, "count": int(v)}
            for k, v in ips.items()
        ]

        return {
            "chartType": "bar",
            "layout": "vertical",
            "meta": {
                "title": "IP Activity",
                "description": "Most active IP addresses"
            },
            "xKey": "ip",
            "series": [{
                "dataKey": "count",
                "label": "Events",
                "valueFormat": "integer"
            }],
            "data": data
        }

    # 4. Line Chart
    def user_graph(self, df):

        users = df["Username"].value_counts()

        data = [
            {"user": k, "count": int(v)}
            for k, v in users.items()
        ]

        return {
            "chartType": "line",
            "meta": {
                "title": "User Activity",
                "description": "Activity by users"
            },
            "xKey": "user",
            "series": [{
                "dataKey": "count",
                "label": "Activity",
                "valueFormat": "integer"
            }],
            "data": data
        }

    # 5. Status Chart
    def status_graph(self, df):

        status = df["Status"].value_counts()

        data = [
            {"status": k, "count": int(v)}
            for k, v in status.items()
        ]

        return {
            "chartType": "pie",
            "meta": {
                "title": "Status Distribution",
                "description": "Success, Failed, Detected"
            },
            "nameKey": "status",
            "valueKey": "count",
            "series": [{
                "dataKey": "count",
                "label": "Count",
                "valueFormat": "integer"
            }],
            "data": data
        }