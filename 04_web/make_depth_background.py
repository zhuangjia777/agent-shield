#!/usr/bin/env python3
"""L0 背景生成器：单点透视立方柱隧道（面向用户、向屏幕内无限延伸）。

- 相机在 (0, h)；每列立方柱固定在视口水平位置，沿视线向深处堆叠：
  x_world = dx * z / F → 正面始终平行屏幕，顶/底线延长后精确过消失点 (CX, CY)。
- 只画 front + top + 面向相机的单侧；size < 0.7px 截断 + 线性渐隐 = "无限延伸"。
- 两块淡出线性：stroke 34 步、fill 10 步 → 远处消散而非截断。
- 输出文件可直接替换 app.py 里两条 --depth-columns token。

用法： python3 make_depth_background.py   # 重打 /tmp/depth_light.css 和 /tmp/depth_dark.css
"""
import base64
import math
import sys
import xml.sax.saxutils as sxu

W, H = 1600, 1000
CX, CY = 800, 60            # 消失点：首屏顶部中央（盖住 body 之后≠0）
F = 1400.0
h = 400.0
A = 80.0
zb, zt = h, h - A
C = 1.09
Z0 = 880.0
SXS = [-1000, -700, -450, 450, 700, 1000]
CENTER_DX = 20
STEPS_MAX = int(math.log(0.8 / (F * A / Z0)) / math.log(C)) + 10   # size 到 0.8px 所需步数

def proj(x, y, z):
    return (CX + F * x / z, CY + F * y / z)

def poly(pts):
    return "M" + " ".join(f"{a:.0f} {b:.0f}" for a, b in pts) + "Z"

def faces(xw, z0):
    """列上的立方柱；front + top + 面向相机侧。返回 [(z, top, front, side)…]。"""
    out = []
    z = z0
    while z <= Z0 * C ** 80:
        if F * A / z < 0.7:
            break
        z2 = z * C
        x0, x1 = xw - A / 2, xw + A / 2
        xe = x1 if xw < 0 else x0

        def P(x, zz):
            px = CX + F * x / zz
            return (px, CY + F * zt / zz), (px, CY + F * zb / zz)

        (x0t, x0b), (x1t, x1b) = P(x0, z), P(x1, z)
        front = [x0t, x1t, x1b, x0b]
        top = [x0t, x1t,
               (CX + F * x1 / z2, CY + F * zt / z2),
               (CX + F * x0 / z2, CY + F * zt / z2)]
        side = [(CX + F * xe / z, CY + F * zt / z),
                (CX + F * xe / z, CY + F * zb / z),
                (CX + F * xe / z2, CY + F * zb / z2),
                (CX + F * xe / z2, CY + F * zt / z2)]
        out.append((z, poly(top), poly(front), poly(side)))
        z = z2
    return out

def build(theme):
    cols = [(sx, Z0) for sx in SXS] + [(CENTER_DX, Z0 * C ** 2)]
    allf = []
    for xw, z_base in cols:
        col = faces(xw, z_base)
        for (z, d_t, d_f, d_s) in col:
            steps = math.log(z / z_base) / math.log(C)   # 本列已深入几步
            f = max(0.0, 1.0 - steps / 10.0)             # fill：10 步内消散
            g = max(0.0, 1.0 - steps / 34.0)             # stroke：34 步内消散
            allf.append((z, d_t, theme.fill_t, f, g * 0.90))
            allf.append((z, d_f, theme.fill_f, f, g * 1.00))
            allf.append((z, d_s, theme.fill_s, f * 0.92, g * 0.95))
    allf.sort(key=lambda t: -t[0])
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" preserveAspectRatio="xMidYMin slice" role="presentation" aria-hidden="true">']
    parts.append(
        '<defs><radialGradient id="dgr" cx="50%" cy="6%" r="95%">'
        '<stop offset="0%" stop-color="#fff"/><stop offset="60%" stop-color="#fff"/>'
        '<stop offset="100%" stop-color="#fff" stop-opacity="0"/></radialGradient>'
        '<mask id="dm" maskUnits="userSpaceOnUse" x="0" y="0" width="' + str(W) + '" height="' + str(H) + '">'
        '<rect width="' + str(W) + '" height="' + str(H) + '" fill="url(#dgr)"/></mask></defs>')
    parts.append('<g mask="url(#dm)">')
    parts.append('<g fill="none" stroke="none">')
    for (z, d, k, fa, sa) in allf:
        if fa > 0.02:
            parts.append(f'<path d="{d}" fill="{k}" opacity="{fa:.2f}"/>')
    parts.append('</g>')
    parts.append(f'<g fill="none" stroke="{theme.stroke}" stroke-width="1" stroke-linejoin="round">')
    for (z, d, k, fa, sa) in allf:
        if sa > 0.02:
            parts.append(f'<path d="{d}" opacity="{sa:.2f}"/>')
    # 两堵墙顶/底 → 消失点 引导线
    for x_end in (-1100, 1100):
        for y_w in (zt, zb):
            px, py = proj(x_end, y_w, Z0)
            parts.append(f'<line x1="{px:.0f}" y1="{max(0,min(H,py)):.0f}" x2="{CX}" y2="{CY}" opacity="{theme.line_op}"/>')
    parts.append("</g></g></svg>")  # stroke g, mask g, svg
    return "".join(parts)

def b64_uri(svg):
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")

class T: pass
def theme(name):
    t = T()
    d = THEMES[name]
    t.fill_t, t.fill_f, t.fill_s = d["fill_t"], d["fill_f"], d["fill_s"]
    t.stroke, t.line_op = d["stroke"], d["line_op"]
    return t

THEMES = {
    "light": dict(fill_t="#e6e6e6", fill_f="#f1f1f1", fill_s="#d3d3d3",
                  stroke="#9b9b9b", line_op=0.13),
    "dark":  dict(fill_t="#101010", fill_f="#1b1b1b", fill_s="#0c0c0c",
                  stroke="#6e6e6e", line_op=0.16),
}

def main():
    for name in ("light", "dark"):
        svg = build(theme(name))
        uri = b64_uri(svg)
        n = svg.count("<path")
        path = f"/tmp/depth_{name}.css"
        with open(path, "w") as f:
            f.write('  --depth-columns: url("%s");\n' % uri)
        print("%s: svg %d chars, %d faces -> %s" % (name, len(svg), n, path))

if __name__ == "__main__":
    main()
