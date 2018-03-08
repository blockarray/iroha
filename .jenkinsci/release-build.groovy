#!/usr/bin/env groovy

def doReleaseBuild() {
	def parallelism = env.PARALLELISM
	if ("arm7" in env.NODE_NAME) {
		parallelism = 1
	}
	def platform = sh(script: 'uname -m', returnStdout: true).trim()
	sh "curl -L -o /tmp/${env.GIT_COMMIT}/Dockerfile --create-dirs https://raw.githubusercontent.com/hyperledger/iroha/${env.GIT_COMMIT}/docker/develop/${platform}/Dockerfile"
	// pull docker image for building release package of Iroha
	// speeds up consequent image builds as we simply tag them 
	sh "docker pull ${DOCKER_BASE_IMAGE_DEVELOP}"
	if (env.BRANCH_NAME == 'master') {
	    iC = docker.build("hyperledger/iroha:${GIT_COMMIT}-${BUILD_NUMBER}", "-f /tmp/${env.GIT_COMMIT}/Dockerfile /tmp/${env.GIT_COMMIT} --build-arg PARALLELISM=${parallelism}")
	}

	sh "mkdir /tmp/${env.GIT_COMMIT}-${BUILD_NUMBER}"
	iC.inside(""
		+ " -v /tmp/${GIT_COMMIT}-${BUILD_NUMBER}:/tmp/${GIT_COMMIT}"
	    + " -v /var/jenkins/ccache:${CCACHE_DIR}") {

	    def scmVars = checkout scm
	    env.IROHA_VERSION = "0x${scmVars.GIT_COMMIT}"
	    env.IROHA_HOME = "/opt/iroha"
	    env.IROHA_BUILD = "${env.IROHA_HOME}/build"
	    env.IROHA_RELEASE = "${env.IROHA_HOME}/docker/release"

	    sh """
	        ccache --version
	        ccache --show-stats
	        ccache --zero-stats
	        ccache --max-size=5G
	    """    
	    sh """
	        cmake \
	          -H. \
	          -Bbuild \
	          -DCMAKE_BUILD_TYPE=${params.BUILD_TYPE} \
	          -DIROHA_VERSION=${env.IROHA_VERSION}
	    """
	    sh "cmake --build build -- -j${parallelism}"
	    sh "ccache --show-stats"
	    // copy build package to the volume
	    sh "cp ${IROHA_BUILD}/iroha.deb /tmp/${GIT_COMMIT}"
	}

	sh "curl -L -o /tmp/${env.GIT_COMMIT}/Dockerfile --create-dirs https://raw.githubusercontent.com/hyperledger/iroha/${env.GIT_COMMIT}/docker/release/${platform}/Dockerfile"
	// pull docker Iroha release image
	// speeds up consequent image builds as we simply tag them 
	// TODO: iroha.deb package is now in the /tmp/${GIT_COMMIT}-${BUILD_NUMBER} directory. Think on how to add it to the release Dockerfile
	sh "docker pull ${DOCKER_BASE_IMAGE_RELEASE}"
	if (env.BRANCH_NAME == 'master') {
	    iC = docker.build("hyperledger/iroha:${GIT_COMMIT}-${BUILD_NUMBER}", "-f /tmp/${env.GIT_COMMIT}/Dockerfile /tmp/${env.GIT_COMMIT} --build-arg iroha-deb-path=/tmp/${GIT_COMMIT}-${BUILD_NUMBER}/build/iroha.deb")
	    docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials'){
        	iC.push("${platform}")
        }
	}
	// remove folder with iroha.deb package and Dockerfiles
	sh """
		rm -rf /tmp/${env.GIT_COMMIT}-${BUILD_NUMBER}
		rm -rf /tmp/${env.GIT_COMMIT}
	"""

}
return this
