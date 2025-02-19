/* Draw text on screen.
 * Requires freetype library.
 * Code is taken from "OpenGL source examples from the OpenGL Programming wikibook:
 * http://en.wikibooks.org/wiki/OpenGL_Programming"
 */

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <algorithm>
#include <assert.h>

#include "Platform.h"
#include "DisplayWindow.h"
#include "GraphicsDrawer.h"
#include "Textures.h"
#include "Config.h"
#include "Log.h"

#include "Graphics/Context.h"
#include "Graphics/Parameters.h"

#include "TextDrawer.h"

#include <osal_files.h>

#ifdef MUPENPLUSAPI
#include "mupenplus/GLideN64_mupenplus.h"
#endif

using namespace graphics;

// Maximum texture width
#define MAXWIDTH 1024

TextDrawer g_textDrawer;

/**
 * The atlas struct holds a texture that contains the visible US-ASCII characters
 * of a certain font rendered with a certain character height.
 * It also contains an array that contains all the information necessary to
 * generate the appropriate vertex and texture coordinates for each character.
 *
 * After the constructor is run, you don't need to use any FreeType functions anymore.
 */
struct Atlas {
	CachedTexture * m_pTexture;	// texture object

	int w;			// width of texture in pixels
	int h;			// height of texture in pixels

	struct {
		float ax;	// advance.x
		float ay;	// advance.y

		float bw;	// bitmap.width;
		float bh;	// bitmap.height;

		float bl;	// bitmap_left;
		float bt;	// bitmap_top;

		float tx;	// x offset of glyph in texture coordinates
		float ty;	// y offset of glyph in texture coordinates
	} c[128];		// character information

	Atlas()
	{

		int roww = 0;
		int rowh = 0;
		w = 0;
		h = 0;

		memset(c, 0, sizeof c);


		w = std::max(w, roww);
		h += rowh;

		/* Create a texture that will be used to hold all ASCII glyphs */
		const FramebufferTextureFormats & fbTexFormats = gfxContext.getFramebufferTextureFormats();

		m_pTexture = textureCache().addFrameBufferTexture(textureTarget::TEXTURE_2D);
		m_pTexture->format = G_IM_FMT_I;
		m_pTexture->clampS = 1;
		m_pTexture->clampT = 1;
		m_pTexture->frameBufferTexture = CachedTexture::fbOneSample;
		m_pTexture->maskS = 0;
		m_pTexture->maskT = 0;
		m_pTexture->mirrorS = 0;
		m_pTexture->mirrorT = 0;
		m_pTexture->width = w;
		m_pTexture->height = h;
		m_pTexture->textureBytes = m_pTexture->width * m_pTexture->height * fbTexFormats.fontFormatBytes;

		Context::InitTextureParams initParams;
		initParams.handle = m_pTexture->name;
		initParams.textureUnitIndex = textureIndices::Tex[0];
		initParams.width = w;
		initParams.height = h;
		initParams.internalFormat = fbTexFormats.fontInternalFormat;
		initParams.format = fbTexFormats.fontFormat;
		initParams.dataType = fbTexFormats.fontType;
		gfxContext.init2DTexture(initParams);

		Context::TexParameters setParams;
		setParams.handle = m_pTexture->name;
		setParams.textureUnitIndex = textureIndices::Tex[0];
		setParams.target = textureTarget::TEXTURE_2D;
		setParams.minFilter = textureParameters::FILTER_LINEAR;
		setParams.magFilter = textureParameters::FILTER_LINEAR;
		setParams.wrapS = textureParameters::WRAP_CLAMP_TO_EDGE;
		setParams.wrapT = textureParameters::WRAP_CLAMP_TO_EDGE;
		gfxContext.setTextureParameters(setParams);

		/* Paste all glyph bitmaps into the texture, remembering the offset */

		/* We require 1 byte alignment when uploading texture data */
		const s32 curUnpackAlignment = gfxContext.getTextureUnpackAlignment();
		gfxContext.setTextureUnpackAlignment(1);

		Context::UpdateTextureDataParams updateParams;
		updateParams.handle = m_pTexture->name;
		updateParams.textureUnitIndex = textureIndices::Tex[0];
		updateParams.format = initParams.format;
		updateParams.internalFormat = initParams.internalFormat;
		updateParams.dataType = initParams.dataType;

		int ox = 0;
		int oy = 0;
		rowh = 0;

		gfxContext.setTextureUnpackAlignment(curUnpackAlignment);

		LOG(LOG_VERBOSE, "Generated a %d x %d (%d kb) texture atlas", w, h, w * h / 1024);
	}

	~Atlas() {
		textureCache().removeFrameBufferTexture(m_pTexture);
		m_pTexture = nullptr;
	}
};

static
bool getFontFileName(char * _strName)
{
#ifdef OS_WINDOWS
	char * pSysPath = getenv("WINDIR");
	if (pSysPath == nullptr)
		return false;
	sprintf(_strName, "%s/Fonts/%s", pSysPath, config.font.name.c_str());
#elif defined (OS_ANDROID)
	sprintf(_strName, "/system/fonts/%s", config.font.name.c_str());
#elif defined (PANDORA)
	sprintf(_strName, "/usr/share/fonts/truetype/%s", config.font.name.c_str());
#else
	sprintf(_strName, "/usr/share/fonts/truetype/freefont/%s", config.font.name.c_str());
#endif

	// if the font name is a full path, use that instead
	if (osal_path_existsA(config.font.name.c_str())) {
		sprintf(_strName, "%s", config.font.name.c_str());
	}

#ifdef MUPENPLUSAPI
	if (!osal_path_existsA(_strName)) {
		const char * fontPath = ConfigGetSharedDataFilepath("font.ttf");
		if (osal_path_existsA(fontPath))
			strncpy(_strName, fontPath, PLUGIN_PATH_SIZE);
	}
#endif
	return true;
}


void TextDrawer::init()
{
	char strBuffer[PLUGIN_PATH_SIZE];
	const char *fontfilename;
	if (getFontFileName(strBuffer))
		fontfilename = strBuffer;
	else
		return;


	/* Create texture atlas for selected font size */

	m_program.reset(gfxContext.createTextDrawerShader());
}

void TextDrawer::destroy()
{
	m_atlas.reset();
	m_program.reset();
}

/**
 * Render text using the currently loaded font and currently set font size.
 * Rendering starts at coordinates (x, y), z is always 0.
 * The pixel coordinates that the FreeType2 library uses are scaled by (sx, sy).
 */
void TextDrawer::drawText(const char *_pText, float _x, float _y) const
{
	if (!m_atlas)
		return;

	DisplayWindow & wnd = DisplayWindow::get();
	const float sx = 2.0f / wnd.getWidth();
	const float sy = 2.0f / wnd.getHeight();

	const u8 *p;


	std::vector<RectVertex> coords;
	coords.reserve(6 * strlen(_pText));

	RectVertex rect;
	rect.z = 0.0f;
	rect.w = 1.0f;

	/* Loop through all characters */
	for (p = (const u8 *)_pText; *p; ++p) {
		/* Calculate the vertex and texture coordinates */
		float x2 = _x + m_atlas->c[*p].bl * sx;
		float y2 = -_y - m_atlas->c[*p].bt * sy;
		float w = m_atlas->c[*p].bw * sx;
		float h = m_atlas->c[*p].bh * sy;

		/* Advance the cursor to the start of the next character */
		_x += m_atlas->c[*p].ax * sx;
		_y += m_atlas->c[*p].ay * sy;

		/* Skip glyphs that have no pixels */
		if (!w || !h)
			continue;

		rect.x = x2;
		rect.y = -y2;
		rect.s0 = m_atlas->c[*p].tx;
		rect.t0 = m_atlas->c[*p].ty;
		coords.push_back(rect);

		rect.x = x2 + w;
		rect.y = -y2;
		rect.s0 = m_atlas->c[*p].tx + m_atlas->c[*p].bw / m_atlas->w;
		rect.t0 = m_atlas->c[*p].ty;
		coords.push_back(rect);

		rect.x = x2;
		rect.y = -y2 - h;
		rect.s0 = m_atlas->c[*p].tx;
		rect.t0 = m_atlas->c[*p].ty + m_atlas->c[*p].bh / m_atlas->h;
		coords.push_back(rect);

		rect.x = x2 + w;
		rect.y = -y2;
		rect.s0 = m_atlas->c[*p].tx + m_atlas->c[*p].bw / m_atlas->w;
		rect.t0 = m_atlas->c[*p].ty;
		coords.push_back(rect);

		rect.x = x2;
		rect.y = -y2 - h;
		rect.s0 = m_atlas->c[*p].tx;
		rect.t0 = m_atlas->c[*p].ty + m_atlas->c[*p].bh / m_atlas->h;
		coords.push_back(rect);

		rect.x = x2 + w;
		rect.y = -y2 - h;
		rect.s0 = m_atlas->c[*p].tx + m_atlas->c[*p].bw / m_atlas->w;
		rect.t0 = m_atlas->c[*p].ty + m_atlas->c[*p].bh / m_atlas->h;
		coords.push_back(rect);
	}

	gfxContext.enable(enable::BLEND, true);
	gfxContext.enable(enable::CULL_FACE, false);
	gfxContext.enable(enable::DEPTH_TEST, false);
	gfxContext.enableDepthWrite(false);
	gfxContext.setBlending(blend::SRC_ALPHA, blend::ONE_MINUS_SRC_ALPHA);
	m_program->activate();

	const s32 X = (wnd.getScreenWidth() - wnd.getWidth()) / 2;
	const s32 Y = (wnd.getScreenHeight() - wnd.getHeight()) / 2 + wnd.getHeightOffset();
	const s32 W = static_cast<s32>(wnd.getWidth());
	const s32 H = static_cast<s32>(wnd.getHeight());

	gfxContext.setViewport(X, Y, W, H);
	gfxContext.setScissor(X, Y, W, H);

	gSP.changed |= CHANGED_VIEWPORT;
	gDP.changed |= CHANGED_SCISSOR;

	Context::TexParameters setParams;
	setParams.handle = m_atlas->m_pTexture->name;
	setParams.textureUnitIndex = textureIndices::Tex[0];
	setParams.target = textureTarget::TEXTURE_2D;
	setParams.minFilter = textureParameters::FILTER_LINEAR;
	setParams.magFilter = textureParameters::FILTER_LINEAR;
	setParams.wrapS = textureParameters::WRAP_CLAMP_TO_EDGE;
	setParams.wrapT = textureParameters::WRAP_CLAMP_TO_EDGE;
	setParams.maxMipmapLevel = Parameter(0);
	gfxContext.setTextureParameters(setParams);

	Context::DrawRectParameters rectParams;
	rectParams.mode = drawmode::TRIANGLES;
	rectParams.verticesCount = static_cast<u32>(coords.size());
	rectParams.vertices = coords.data();
	rectParams.combiner = m_program.get();
	gfxContext.drawRects(rectParams);
}

void TextDrawer::getTextSize(const char *_pText, float & _w, float & _h) const
{
	_w = _h = 0;
	if (!m_atlas)
		return;

	DisplayWindow & wnd = DisplayWindow::get();
	const float sx = 2.0f / wnd.getWidth();
	const float sy = 2.0f / wnd.getHeight();
	float bw = 0, bh = 0;

	for (const u8 *p = (const u8 *)_pText; *p; ++p) {
		bw = m_atlas->c[*p].bw * sx;
		bh = std::max(bh, m_atlas->c[*p].bh * sy);

		_w += m_atlas->c[*p].ax * sx;
//		_h += m_atlas->c[*p].ay * sy;
	}
	_w += bw;
	_h += bh;
}

void TextDrawer::setTextColor(float * _color)
{
	if (m_program)
		m_program->setTextColor(_color);
}
