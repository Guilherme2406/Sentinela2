# assets/generate_icon.py
import os
from PIL import Image, ImageDraw

def generate_sentinel_icons():
    assets_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(assets_dir, exist_ok=True)

    size = (256, 256)
    img = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Desenha um escudo estilizado Cyberpunk
    # Fundo do escudo
    shield_pts = [
        (128, 16),
        (224, 52),
        (210, 165),
        (128, 236),
        (46, 165),
        (32, 52)
    ]
    
    # Borda Externa Ciano Neon
    draw.polygon(shield_pts, fill=(17, 22, 34, 255), outline=(0, 240, 255, 255), width=8)

    # Escudo Interno
    inner_pts = [
        (128, 38),
        (202, 66),
        (190, 155),
        (128, 214),
        (66, 155),
        (54, 66)
    ]
    draw.polygon(inner_pts, fill=(8, 11, 17, 255), outline=(16, 185, 129, 255), width=4)

    # Símbolo Central: Vértice de Proteção / Shield Crosshair
    draw.line([(128, 70), (128, 180)], fill=(0, 240, 255, 255), width=6)
    draw.line([(85, 120), (171, 120)], fill=(0, 240, 255, 255), width=6)
    draw.ellipse([(112, 104), (144, 136)], outline=(0, 240, 255, 255), width=5)
    draw.ellipse([(120, 112), (136, 128)], fill=(16, 185, 129, 255))

    # Salva PNG
    png_path = os.path.join(assets_dir, "sentinel_icon.png")
    img.save(png_path, "PNG")

    # Salva ICO com múltiplos tamanhos
    ico_path = os.path.join(assets_dir, "sentinel_icon.ico")
    img.save(ico_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

    print(f"[OK] Icones gerados em: {png_path} e {ico_path}")

if __name__ == "__main__":
    generate_sentinel_icons()
