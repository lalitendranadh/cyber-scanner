import requests
import folium
import webbrowser
import os

def get_ip_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return res.get("lat"), res.get("lon"), res.get("country")
    except:
        return None, None, "Unknown"

def generate_map(ip_list):
    world_map = folium.Map(location=[20,0], zoom_start=2)

    for ip in ip_list:
        lat, lon, country = get_ip_location(ip)
        if lat and lon:
            folium.Marker([lat, lon], popup=f"{ip} ({country})").add_to(world_map)

    map_file = "ip_map.html"
    world_map.save(map_file)
    webbrowser.open('file://' + os.path.realpath(map_file))
