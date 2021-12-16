-- SQL Dump
--

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


-- --------------------------------------------------------

--
-- Table structure for table `threads`
--

CREATE TABLE IF NOT EXISTS `threads` (
  `id` int(11) NOT NULL auto_increment,
  `username` varchar(20) NOT NULL,
  `title` varchar(50) NOT NULL,
  `message` text NOT NULL,
  `date` bigint(20) NOT NULL,
  PRIMARY KEY  (`id`),
  KEY `UNAME_FK` (`username`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=4 ;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `username` char(20) NOT NULL,
  `pass` char(40) NOT NULL,
  `fname` varchar(25) NOT NULL,
  `lname` varchar(25) NOT NULL,
  `extra` varchar(64) NOT NULL DEFAULT '0' COMMENT 'if needed in the future',
  `extra2` varchar(160) NOT NULL DEFAULT '0' COMMENT 'if you need 2',
  PRIMARY KEY  (`username`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COMMENT='Table containing user information. username should be unique';

