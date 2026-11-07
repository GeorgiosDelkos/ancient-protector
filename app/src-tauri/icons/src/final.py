import math, sys
sys.argv=["x"]; exec(open("gen.py").read().split("V = {")[0])
def lerp(c1, c2, t):
    a=[int(c1[i:i+2],16) for i in (1,3,5)]; b=[int(c2[i:i+2],16) for i in (1,3,5)]
    return "#"+"".join(f"{round(a[i]+(b[i]-a[i])*t):02x}" for i in range(3))
def centred(ds, size=24):
    xs=[x-r for x,y,r,t in ds]+[x+r for x,y,r,t in ds]; ys=[y-r for x,y,r,t in ds]+[y+r for x,y,r,t in ds]
    dx=size/2-(min(xs)+max(xs))/2; dy=size/2-(min(ys)+max(ys))/2
    return [(x+dx,y+dy,r,t) for x,y,r,t in ds]
def circles(ds, fill): return "".join(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" fill="{fill(t)}"/>' for x,y,r,t in ds)
app=centred(arm(26, 1.8, 9.8, 0.22, 1.55, start=0.06))
tray=centred(arm(13, 1.55, 9.9, 0.55, 1.95, start=0.1))
bg=open("app-A.svg").read().split('<g transform')[0]
open("icon.svg","w").write(bg+'<g transform="translate(512 512) scale(27) translate(-12 -12)">'+circles(app, lambda t: lerp("#5b84f0","#f2f5fb",t**0.8))+'</g></svg>\n')
open("mark.svg","w").write('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'+circles(tray, lambda t:"currentColor")+'</svg>\n')
