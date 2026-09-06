# cloud_app.py
"""
Entrypoint oficial para deploy no Vercel (Cloud Console).
Exporta a instância do Flask app para Vercel Serverless Functions.
"""

from api.index import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
