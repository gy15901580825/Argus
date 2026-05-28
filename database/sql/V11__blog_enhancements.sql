-- ============================================================================
-- V11: Blog System Enhancements
-- Categories, Tags, Media Assets, Blog Authors, Full-text Search, View Tracking
-- ============================================================================

-- 1. Blog Categories (hierarchical, two-level)
CREATE TABLE blog_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(120) UNIQUE NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES blog_categories(id) ON DELETE SET NULL,
    sort_order INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Blog Tags
CREATE TABLE blog_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) NOT NULL,
    slug VARCHAR(60) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. Blog-Tag many-to-many
CREATE TABLE blog_tag_map (
    blog_id UUID NOT NULL REFERENCES blogs(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES blog_tags(id) ON DELETE CASCADE,
    PRIMARY KEY (blog_id, tag_id)
);

-- 4. Media Assets (R2 resource management)
CREATE TABLE media_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    filename VARCHAR(500) NOT NULL,
    r2_key TEXT NOT NULL UNIQUE,
    r2_url TEXT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    width INT,
    height INT,
    alt_text VARCHAR(300),
    uploaded_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 5. Blog Authors (admin-designated publishing rights)
CREATE TABLE blog_authors (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    display_name VARCHAR(100) NOT NULL,
    bio TEXT,
    avatar_url TEXT,
    granted_by UUID NOT NULL REFERENCES users(id),
    granted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 6. Blog Views (lightweight analytics)
CREATE TABLE blog_views (
    id BIGSERIAL PRIMARY KEY,
    blog_id UUID NOT NULL REFERENCES blogs(id) ON DELETE CASCADE,
    viewer_ip INET,
    user_agent TEXT,
    referer TEXT,
    viewed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 7. Extend blogs table
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS slug VARCHAR(300) UNIQUE;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS category_id UUID REFERENCES blog_categories(id) ON DELETE SET NULL;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS cover_image_url TEXT;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS meta_title VARCHAR(120);
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS meta_description VARCHAR(320);
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS og_image_url TEXT;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS canonical_url TEXT;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS reading_time_min INT DEFAULT 1;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS view_count INT DEFAULT 0;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS content_format VARCHAR(20) DEFAULT 'html';
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT FALSE;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'draft';
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS locale VARCHAR(10) DEFAULT 'en';

-- 8. Extend comments table
ALTER TABLE comments ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'approved';
ALTER TABLE comments ADD COLUMN IF NOT EXISTS likes_count INT DEFAULT 0;

-- 9. Full-text search vector
ALTER TABLE blogs ADD COLUMN IF NOT EXISTS search_vector tsvector;

-- 10. Indexes
CREATE INDEX IF NOT EXISTS idx_blogs_slug ON blogs(slug);
CREATE INDEX IF NOT EXISTS idx_blogs_category ON blogs(category_id);
CREATE INDEX IF NOT EXISTS idx_blogs_published ON blogs(is_published, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_blogs_status ON blogs(status, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_blogs_featured ON blogs(featured, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_blogs_search ON blogs USING GIN(search_vector);
CREATE INDEX IF NOT EXISTS idx_blog_tags_slug ON blog_tags(slug);
CREATE INDEX IF NOT EXISTS idx_blog_categories_slug ON blog_categories(slug);
CREATE INDEX IF NOT EXISTS idx_blog_categories_parent ON blog_categories(parent_id);
CREATE INDEX IF NOT EXISTS idx_media_uploaded_by ON media_assets(uploaded_by);
CREATE INDEX IF NOT EXISTS idx_blog_views_blog ON blog_views(blog_id, viewed_at);

-- 11. Full-text search trigger
CREATE OR REPLACE FUNCTION blogs_search_vector_update() RETURNS trigger AS $$
BEGIN
    NEW.search_vector :=
        setweight(to_tsvector('english', COALESCE(NEW.title, '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(NEW.summary, '')), 'B') ||
        setweight(to_tsvector('english', COALESCE(NEW.content, '')), 'C');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER blogs_search_vector_trigger
    BEFORE INSERT OR UPDATE OF title, summary, content ON blogs
    FOR EACH ROW EXECUTE FUNCTION blogs_search_vector_update();

-- 12. Auto-calculate reading time
CREATE OR REPLACE FUNCTION calculate_reading_time() RETURNS trigger AS $$
BEGIN
    NEW.reading_time_min := GREATEST(1,
        length(regexp_replace(COALESCE(NEW.content, ''), '<[^>]*>', '', 'g')) / 5 / 200
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER blogs_reading_time_trigger
    BEFORE INSERT OR UPDATE OF content ON blogs
    FOR EACH ROW EXECUTE FUNCTION calculate_reading_time();

-- 13. Backfill slugs for existing blogs
UPDATE blogs SET slug = LOWER(REPLACE(REPLACE(REPLACE(title, ' ', '-'), '.', ''), ',', ''))
WHERE slug IS NULL;

-- 14. Backfill status for existing blogs
UPDATE blogs SET status = CASE WHEN is_published THEN 'published' ELSE 'draft' END
WHERE status IS NULL OR status = 'draft';

-- 15. Backfill search vectors for existing blogs
UPDATE blogs SET search_vector =
    setweight(to_tsvector('english', COALESCE(title, '')), 'A') ||
    setweight(to_tsvector('english', COALESCE(summary, '')), 'B') ||
    setweight(to_tsvector('english', COALESCE(content, '')), 'C');

-- 16. Seed default categories
INSERT INTO blog_categories (name, slug, description, sort_order) VALUES
('Tutorials', 'tutorials', 'Step-by-step guides and how-tos', 1),
('Product Updates', 'product-updates', 'New features and improvements', 2),
('Engineering', 'engineering', 'Technical deep-dives and architecture', 3),
('Testing Best Practices', 'testing-best-practices', 'Industry insights and methodologies', 4),
('Case Studies', 'case-studies', 'Customer success stories', 5)
ON CONFLICT (slug) DO NOTHING;
