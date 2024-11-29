from flask import Flask, request, jsonify
from flask_cors import CORS
import asyncio
import aiohttp
import ipaddress
import socket
from ipwhois import IPWhois
from AIPDBmain import aipdbmain
from IPQSmain import ipqsmain
from VTmain import vtmain
from OTXAmain import otxamain

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Helper functions
async def get_domain_and_country(ip_address):
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        domain = "Unknown Domain"

    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        country = result.get('network', {}).get('country', 'Unknown Country')
    except Exception:
        country = "Unknown Country"
    return domain, country

async def process_ip_or_domain(address, index, session):
    try:
        # Check if the input is an IP; otherwise, resolve domain
        try:
            ipaddress.ip_address(address)  # Validate if it's already an IP
        except ValueError:
            address = socket.gethostbyname(address)
    except socket.gaierror:
        return {"error": f"Invalid input '{address}' - Not a valid IP or domain!"}

    domain, country = await get_domain_and_country(address)

    # Call each of the APIs
    aipdb_response, _ = await aipdbmain(address, index, session)
    vt_response, _ = await vtmain(address, index, session)
    ipqs_response = await ipqsmain(address, index, session)
    otxa_response, _ = await otxamain(address, index, session)

    # Prepare result
    result = {
        "IP": address,
        "Domain": domain,
        "Country": country,
        "AbuseIPDB": aipdb_response,
        "VT": vt_response,
        "IPQS": ipqs_response,
        "OTX-A": otxa_response,
    }
    return result

@app.route('/', methods=['GET'])
async def all():
    return jsonify("hi")

@app.route('/analyze', methods=['POST'])
async def analyze():
    data = request.json
    inputs = data.get("inputs", [])

    # Validate inputs
    if not isinstance(inputs, list) or not inputs:
        return jsonify({"error": "Invalid input: 'inputs' must be a non-empty list."}), 400

    # Set up aiohttp client timeout correctly
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [process_ip_or_domain(ip, i, session) for i, ip in enumerate(inputs, start=1)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Handle any errors during processing
    cleaned_results = []
    for result in results:
        if isinstance(result, Exception):
            cleaned_results.append({"error": str(result)})
        else:
            cleaned_results.append(result)

    return jsonify(cleaned_results)

if __name__ == "__main__":
    app.run(debug=True)
